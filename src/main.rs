use anchor_client::anchor_lang::AnchorDeserialize;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as JsonValue};
use std::collections::HashMap;
use std::error::Error;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::{fmt, fs};

use anchor_client::anchor_lang::idl::IdlAccount;
use anchor_client::solana_client::rpc_client::RpcClient;
use anchor_client::solana_sdk::pubkey::Pubkey;
use anchor_syn::idl::{EnumFields, Idl, IdlType, IdlTypeDefinitionTy};

use anchor_syn::idl::IdlInstruction;
use bs58;
use flate2::read::ZlibDecoder;

use clap::Parser;
use heck::{ToSnakeCase, ToUpperCamelCase};

// Transaction JSON-RPC request payload
#[derive(Serialize)]
struct TransactionRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: [&'a str; 2],
}

// JSON-RPC response payload
#[allow(dead_code, non_snake_case)]
#[derive(Deserialize)]
struct TransactionResponse {
    jsonrpc: String,
    id: u64,
    result: Option<TransactionResult>,
}

// Transaction result structure
#[derive(Deserialize)]
struct TransactionResult {
    meta: TransactionMeta,
    transaction: Transaction,
}

// Transaction metadata
#[allow(non_snake_case)]
#[derive(Deserialize)]
struct TransactionMeta {
    innerInstructions: Vec<InnerInstruction>,
    logMessages: Option<Vec<String>>,
}

// InnerInstruction structure
#[derive(Deserialize)]
struct InnerInstruction {
    index: u64,
    instructions: Vec<Instruction>,
}

// Instruction structure
#[allow(non_snake_case)]
#[derive(Deserialize)]
struct Instruction {
    programIdIndex: u64,
    accounts: Vec<u64>,
    data: String,
}

// Transaction structure
#[derive(Deserialize, Debug)]
struct Transaction {
    message: TransactionMessage,
}

// Transaction message structure
#[allow(dead_code, non_snake_case)]
#[derive(Debug, Deserialize)]
struct TransactionMessage {
    accountKeys: Vec<String>,
    header: Header,
    recentBlockhash: String,
    instructions: Vec<Instruction>,
    addressTableLookups: Option<Vec<AddressTableLookup>>,
}

#[allow(dead_code, non_snake_case)]
#[derive(Debug, Deserialize)]
struct Header {
    numRequiredSignatures: u64,
    numReadonlySignedAccounts: u64,
    numReadonlyUnsignedAccounts: u64,
}

#[allow(dead_code, non_snake_case)]
#[derive(Debug, Deserialize)]
struct AddressTableLookup {
    accountKey: String,
    writableIndexes: Vec<u64>,
    readonlyIndexes: Vec<u64>,
}

impl fmt::Display for InnerInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Instruction Index: {}", self.index)?;
        for (i, instruction) in self.instructions.iter().enumerate() {
            writeln!(f, "│  ├─ Inner Instruction {}: ", i + 1)?;
            write!(f, "│  │  ")?;
            fmt::Debug::fmt(instruction, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "ProgramIdIndex: {}, Accounts: {:?}, Data: {}",
            self.programIdIndex, self.accounts, self.data
        )
    }
}

fn unzip_idl(idl_account_data: Vec<u8>, _compressed_len: u32) -> Result<Idl, Box<dyn Error>> {
    let compressed_len: usize = _compressed_len.try_into().unwrap();
    let compressed_bytes = &idl_account_data[44..44 + compressed_len];
    let mut z = ZlibDecoder::new(compressed_bytes);
    let mut s = Vec::new();
    z.read_to_end(&mut s)?;
    serde_json::from_slice(&s[..]).map_err(Into::into)
}

async fn get_and_save_idl(client: &RpcClient, program_id: &Pubkey) -> Result<Idl, Box<dyn Error>> {
    let path = format!("idl/{}.json", program_id);

    let idl: Idl;
    if Path::new(&path).try_exists().unwrap_or(false) {
        // println!("IDL for program {} already exists", program_id);
        let data = fs::read(path)?;
        idl = serde_json::from_slice(&data[..])?;
    } else {
        // println!("Downloaded and saved IDL for program {}", program_id);

        let pubkey = IdlAccount::address(program_id);
        let idl_account_data = client.get_account_data(&pubkey)?;

        let mut d: &[u8] = &idl_account_data.as_slice()[8..];
        let idl_account: IdlAccount = IdlAccount::deserialize(&mut d)?;

        idl = unzip_idl(idl_account_data, idl_account.data_len)?;

        let idl_json = serde_json::to_string_pretty(&idl)?;

        fs::create_dir_all("idl")?;
        fs::write(path, idl_json)?;
    }

    Ok(idl)
}

#[allow(dead_code)]
struct NamedAnchorArgs {
    index: usize,
    name: String,
    value: JsonValue,
}

impl NamedAnchorArgs {
    fn fmt_value(&self, val: &JsonValue, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match val {
            JsonValue::Array(arr) => {
                write!(f, "[")?;
                for (i, v) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", ::serde_json::to_string_pretty(v).unwrap())?;
                }
                write!(f, "]")
            }
            _ => write!(f, "{}", ::serde_json::to_string_pretty(val).unwrap()),
        }
    }
}

impl fmt::Display for NamedAnchorArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.name)?;
        self.fmt_value(&self.value, f)
    }
}

struct ParsedAnchorInstruction {
    name: String,
    args: Vec<NamedAnchorArgs>,
}

fn parse_inner_instruction_using_idl(
    idl: &anchor_syn::idl::Idl,
    instruction: &Instruction,
) -> Result<ParsedAnchorInstruction, Box<dyn Error>> {
    let data = bs58::decode(&instruction.data).into_vec()?;

    let ix_id = &data.as_slice()[..8];
    let idl_instruction = idl.instructions.iter().find(|instr| {
        let id = anchor_syn::codegen::program::common::sighash(
            "global",
            &instr.name.to_string().to_snake_case(),
        );
        ix_id == id
    });

    Ok(match idl_instruction {
        Some(idl_instr) => {
            let args = decode_args_using_ix_idl(&idl, &idl_instr, &instruction)?;
            ParsedAnchorInstruction {
                name: idl_instr.name.replace("\"", ""),
                args,
            }
        }
        None => return Err("No matching instruction found in IDL".into()),
    })
}

// Deserializes a user defined IDL struct/enum by munching the account data.
// Recursively deserializes elements one by one
fn deserialize_idl_struct_to_json(
    idl: &Idl,
    account_type_name: &str,
    data: &mut &[u8],
) -> Result<JsonValue, anyhow::Error> {
    let account_type = &idl
        .accounts
        .iter()
        .chain(idl.types.iter())
        .find(|account_type| account_type.name == account_type_name)
        .ok_or_else(|| {
            anyhow::anyhow!("Struct/Enum named {} not found in IDL.", account_type_name)
        })?
        .ty;

    let mut deserialized_fields = Map::new();

    match account_type {
        IdlTypeDefinitionTy::Struct { fields } => {
            for field in fields {
                deserialized_fields.insert(
                    field.name.clone(),
                    deserialize_idl_type_to_json(&field.ty, data, idl)?,
                );
            }
        }
        IdlTypeDefinitionTy::Enum { variants } => {
            let repr = <u8 as AnchorDeserialize>::deserialize(data)?;

            let variant = variants
                .get(repr as usize)
                .unwrap_or_else(|| panic!("Error while deserializing enum variant {repr}"));

            let mut value = json!({});

            if let Some(enum_field) = &variant.fields {
                match enum_field {
                    anchor_syn::idl::EnumFields::Named(fields) => {
                        let mut values = Map::new();

                        for field in fields {
                            values.insert(
                                field.name.clone(),
                                deserialize_idl_type_to_json(&field.ty, data, idl)?,
                            );
                        }

                        value = JsonValue::Object(values);
                    }
                    EnumFields::Tuple(fields) => {
                        let mut values = Vec::new();

                        for field in fields {
                            values.push(deserialize_idl_type_to_json(field, data, idl)?);
                        }

                        value = JsonValue::Array(values);
                    }
                }
            }

            deserialized_fields.insert(variant.name.clone(), value);
        }
    }

    Ok(JsonValue::Object(deserialized_fields))
}

// Deserializes a primitive type using AnchorDeserialize
fn deserialize_idl_type_to_json(
    idl_type: &IdlType,
    data: &mut &[u8],
    parent_idl: &Idl,
) -> Result<JsonValue, anyhow::Error> {
    if data.is_empty() {
        return Err(anyhow::anyhow!("Unable to parse from empty bytes"));
    }

    Ok(match idl_type {
        IdlType::Bool => json!(<bool as AnchorDeserialize>::deserialize(data)?),
        IdlType::U8 => {
            json!(<u8 as AnchorDeserialize>::deserialize(data)?)
        }
        IdlType::I8 => {
            json!(<i8 as AnchorDeserialize>::deserialize(data)?)
        }
        IdlType::U16 => {
            json!(<u16 as AnchorDeserialize>::deserialize(data)?)
        }
        IdlType::I16 => {
            json!(<i16 as AnchorDeserialize>::deserialize(data)?)
        }
        IdlType::U32 => {
            json!(<u32 as AnchorDeserialize>::deserialize(data)?)
        }
        IdlType::I32 => {
            json!(<i32 as AnchorDeserialize>::deserialize(data)?)
        }
        IdlType::F32 => json!(<f32 as AnchorDeserialize>::deserialize(data)?),
        IdlType::U64 => {
            json!(<u64 as AnchorDeserialize>::deserialize(data)?)
        }
        IdlType::I64 => {
            json!(<i64 as AnchorDeserialize>::deserialize(data)?)
        }
        IdlType::F64 => json!(<f64 as AnchorDeserialize>::deserialize(data)?),
        IdlType::U128 => {
            // TODO: Remove to_string once serde_json supports u128 deserialization
            json!(<u128 as AnchorDeserialize>::deserialize(data)?.to_string())
        }
        IdlType::I128 => {
            // TODO: Remove to_string once serde_json supports i128 deserialization
            json!(<i128 as AnchorDeserialize>::deserialize(data)?.to_string())
        }
        IdlType::U256 => todo!("Upon completion of u256 IDL standard"),
        IdlType::I256 => todo!("Upon completion of i256 IDL standard"),
        IdlType::Bytes => JsonValue::Array(
            <Vec<u8> as AnchorDeserialize>::deserialize(data)?
                .iter()
                .map(|i| json!(*i))
                .collect(),
        ),
        IdlType::String => json!(<String as AnchorDeserialize>::deserialize(data)?),
        IdlType::PublicKey => {
            json!(<Pubkey as AnchorDeserialize>::deserialize(data)?.to_string())
        }
        IdlType::Defined(type_name) => deserialize_idl_struct_to_json(parent_idl, type_name, data)?,
        IdlType::Option(ty) => {
            let is_present = <u8 as AnchorDeserialize>::deserialize(data)?;

            if is_present == 0 {
                JsonValue::String("None".to_string())
            } else {
                deserialize_idl_type_to_json(ty, data, parent_idl)?
            }
        }
        IdlType::Vec(ty) => {
            let size: usize = <u32 as AnchorDeserialize>::deserialize(data)?
                .try_into()
                .unwrap();

            let mut vec_data: Vec<JsonValue> = Vec::with_capacity(size);

            for _ in 0..size {
                vec_data.push(deserialize_idl_type_to_json(ty, data, parent_idl)?);
            }

            JsonValue::Array(vec_data)
        }
        IdlType::Array(ty, size) => {
            let mut array_data: Vec<JsonValue> = Vec::with_capacity(*size);

            for _ in 0..*size {
                array_data.push(deserialize_idl_type_to_json(ty, data, parent_idl)?);
            }

            JsonValue::Array(array_data)
        }
    })
}

fn decode_args_using_ix_idl(
    parent_idl: &Idl,
    idl: &IdlInstruction,
    instruction: &Instruction,
) -> Result<Vec<NamedAnchorArgs>, Box<dyn Error>> {
    let mut args = Vec::new();
    for (idx, arg) in idl.args.iter().enumerate() {
        let bytes = bs58::decode(instruction.data.clone()).into_vec()?;
        let mut data = &bytes[8..];
        let ptr = &mut data;

        for (index, field) in idl.args.iter().enumerate() {
            let arg = deserialize_idl_type_to_json(&field.ty, ptr, parent_idl)?;
            args.push(NamedAnchorArgs {
                index,
                name: field.name.clone(),
                value: arg,
            })
        }
    }
    Ok(args)
}

async fn explore_instruction(
    rpc_client: &RpcClient,
    instruction: &Instruction,
    program_idls: &mut HashMap<Pubkey, Idl>,
    account_keys: &Vec<String>,
    depth: u8,
    last: bool,
) -> Result<(), Box<dyn Error>> {
    let program_id = Pubkey::from_str(&account_keys[instruction.programIdIndex as usize])?;

    let mut idl: Option<Idl> = None;
    if !program_idls.contains_key(&program_id) {
        match get_and_save_idl(&rpc_client, &program_id).await {
            Err(_e) => {
                // eprintln!("Error downloading IDL for program {}: {}", program_id, e);
            }
            Ok(program_idl) => {
                program_idls.insert(program_id, program_idl.clone());
                idl = Some(program_idl);
            }
        }
    } else {
        idl = program_idls.get(&program_id).map(|idl| idl.clone());
    }

    let repeating_phrase = if last { "└─" } else { "| " };
    let final_char = if last { "└─" } else { "├─" };
    let depth_prefix = format!("{}{}", repeating_phrase.repeat(depth.into()), final_char);
    match idl {
        Some(idl) => {
            let result = parse_inner_instruction_using_idl(&idl, &instruction).unwrap();
            println!(
                "{}{}: {}",
                depth_prefix,
                &idl.name.to_upper_camel_case(),
                result.name
            );
            result.args.iter().for_each(|arg| {
                println!("{}—{}", depth_prefix, arg);
            });
        }
        None => {
            println!("{}{} <<unknown>>", depth_prefix, program_id.to_string());
        }
    }
    Ok(())
}

#[derive(Parser)]
struct Cli {
    /// The transaction ID to parse
    tx: String,
}

fn parse() -> Cli {
    Cli::parse()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = parse();
    let transaction_id = String::from(args.tx.clone());

    // let transaction_id =
    //     "5eVBiUwyeWpcp66ecdpiziahCUxbeagPkuZMxV6iQ1QzvPXCijJkL6q4WSzkKNnTUQHnWafJNFQ5vLnRq8neLc9h";
    let url = "https://api.mainnet-beta.solana.com";
    // let url = "https://api.devnet.solana.com";
    let rpc_client = RpcClient::new(url.to_string());
    let client = Client::new();

    let arg: &str = "json";

    let request_payload = TransactionRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getTransaction",
        params: [&transaction_id, arg],
    };

    let response = client
        .post(url)
        .json(&request_payload)
        .send()
        .await?
        .json::<TransactionResponse>()
        .await?;

    println!("Tx: {}", transaction_id);
    if let Some(result) = response.result {
        let account_keys = &result.transaction.message.accountKeys;

        let mut stacktrace = Vec::<u32>::new();
        if let Some(logs) = result.meta.logMessages {
            let re = Regex::new(r"Program (?P<program>.*) invoke \[(?P<depth>.*)\]").unwrap();
            for m in re.captures_iter(&logs.join("\n")) {
                stacktrace.push(m["depth"].parse().unwrap());
            }
        }

        let mut program_idls: HashMap<Pubkey, Idl> = HashMap::new();
        let mut stacktrace_counter: u32 = 0;
        for (i, instruction) in result.transaction.message.instructions.iter().enumerate() {
            let last: bool = i == result.transaction.message.instructions.len() - 1
                && result.meta.innerInstructions.get(i).is_none();
            explore_instruction(
                &rpc_client,
                &instruction,
                &mut program_idls,
                &account_keys,
                0,
                last,
            )
            .await?;
            stacktrace_counter += 1;

            if let Some(inner_ixs) = result.meta.innerInstructions.get(i) {
                for (inner_idx, inner_ix) in inner_ixs.instructions.iter().enumerate() {
                    let last: bool = i == result.transaction.message.instructions.len() - 1
                        && inner_idx == inner_ixs.instructions.len() - 1;

                    let result: Option<&u32> = stacktrace.get::<usize>(stacktrace_counter as usize);
                    let depth: u32 = match result {
                        Some(d) => (*d) - 1,
                        None => 1,
                    };
                    explore_instruction(
                        &rpc_client,
                        &inner_ix,
                        &mut program_idls,
                        &account_keys,
                        depth.to_le_bytes()[0],
                        last,
                    )
                    .await?;

                    stacktrace_counter += 1;
                }
            }
        }
    } else {
        println!("No transaction found for the given ID.");
    }

    Ok(())
}
