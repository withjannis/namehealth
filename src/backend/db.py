import boto3
from boto3.dynamodb.conditions import Key, Attr

session = boto3.Session(
    profile_name="nh-ddb-ro",
    region_name="eu-west-3",
)

dynamodb = session.resource("dynamodb")
table = dynamodb.Table("namehealth-v1")


def get_latest_item(mark: str):
    response = table.query(
        KeyConditionExpression=Key("mark").eq(mark),
        Limit=1,
        ScanIndexForward=False,
    )

    return response["Items"][0]


def get_item(mark: str):
    domain_prefix = "config#domain#"
    response = table.get_item(
        Key={"mark": domain_prefix + mark, "timestamp": 0}
    )

    if "Item" not in response:
        return None
    return response["Item"]


def list_items(query):
    response = table.scan(
        FilterExpression=Attr("mark").begins_with(query),
    )

    return response["Items"]


if __name__ == "__main__":
    print(list_items("config#domain#"))
    print(get_latest_item("cloudflare.com#A"))

    print(get_item("example.com"))
