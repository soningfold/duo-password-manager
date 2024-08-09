import boto3
from botocore.exceptions import ClientError
import json


def create_secret(secret_name, username, password):
    json_data = {"username": username, "password": password}

    encode = json.dumps(json_data)

    client = boto3.client("secretsmanager")

    try:
        client.create_secret(Name=secret_name, SecretString=encode)
    except ClientError:
        return f"{secret_name} already exists."

    return f"{secret_name} has been stored successfully"


def get_secret(secret_name):

    secret_name = secret_name
    region_name = "eu-west-2"

    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager",
                            region_name=region_name)

    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError:
        return f"{secret_name} was not found."

    secret = response["SecretString"]

    with open("./data/secret.txt", "w", encoding="utf-8") as f:
        f.write(secret)

    return f"{secret_name} has been stored in a file successfully"


def list_secrets():
    client = boto3.client("secretsmanager")
    response = client.list_secrets()
    list_secret = [secret["Name"] for secret in response["SecretList"]]
    return list_secret


def delete_secret(secret_name):
    client = boto3.client("secretsmanager")
    client.delete_secret(
        SecretId=secret_name, ForceDeleteWithoutRecovery=True
    )
    return f"{secret_name} has been successfully deleted!"


def random_password():
    client = boto3.client("secretsmanager")
    response = client.get_random_password(PasswordLength=64)
    return response['RandomPassword']


def password_manager():
    exit_clause = False
    while not exit_clause:
        message = "Please specify [e]ntry, [r]etrieval, [d]eletion, [l]isting, random [p]assword or e[x]it:\n"
        menu = input(message)
        if menu == "e":
            secret_name = input("Secret name:\n")
            username = input("Username:\n")
            password = input("Password:\n")
            print(create_secret(secret_name, username, password))
        if menu == "r":
            secret_name = input("Secret to retrieve:\n")
            print(get_secret(secret_name))
        if menu == "d":
            secret_name = input("Secret to delete:\n")
            print(delete_secret(secret_name))
        if menu == "l":
            print("See list of secrets:")
            print(list_secrets())
        if menu == "p":
            print("Here is a randomly generated 64 character password:")
            print(random_password())
        if menu == "x":
            print("Thank you for using the password manager!")
            exit_clause = True


if __name__ == "__main__":
    password_manager()
