use aws_sdk_dynamodb::operation::{put_item::PutItemOutput, get_item::GetItemOutput};
use aws_sdk_dynamodb::{Client};

use aws_sdk_dynamodb::types::AttributeValue;

#[derive(Debug, Clone)]
pub struct Item {
    pk: (String, AttributeValue),
    rk: (String, AttributeValue),
    kv: Vec<(String, AttributeValue)>
}

impl Item {
    pub fn new(
        pk: (String, AttributeValue),
        rk: (String, AttributeValue),
        kv: Vec<(String, AttributeValue)>
    ) -> Self {
        Item { pk: pk, rk: rk, kv: kv}
    }
}

pub async fn get_item(
    client: &Client,
    table: String,
    item: Item
    ) -> Result<GetItemOutput, ()> {
    let request = client
        .get_item()
        .table_name(table)
        .key(item.pk.0, item.pk.1)
        .key(item.rk.0, item.rk.1);

    println!("Executing request to add item...", );

    let result = request.send().await;

    println!("Finished to add item...");

    match result{
        Ok(o) => return Ok(o),
        Err(e) => {
            println!("{:?}", e);
            Err(())
        }
    }
}
pub async fn add_item(
    client: &Client,
    table: String,
    item: Item
    ) -> Result<PutItemOutput, ()> {
    let mut request = client
        .put_item()
        .table_name(table)
        .item(item.pk.0, item.pk.1)
        .item(item.rk.0, item.rk.1);
    
    for (k , v) in item.kv{
        request = request.item(k, v);
    }

    println!("Executing request to add item...", );

    let result = request.send().await;

    println!("Finished to add item...");

    match result{
        Ok(o) => return Ok(o),
        Err(e) => {
            println!("{:?}", e);
            Err(())
        }
    }
}