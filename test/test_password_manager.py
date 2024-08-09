from src.password_manager import create_secret, random_password
from src.password_manager import get_secret, list_secrets, delete_secret
from moto import mock_aws
import pytest
import boto3
import os


@pytest.fixture
def aws_creds():
    os.environ["AWS_ACCESS_KEY_ID"] = "test"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "test"
    os.environ["AWS_SECURITY_TOKEN"] = "test"
    os.environ["AWS_SESSION_TOKEN"] = "test"
    os.environ["AWS_DEFAULT_REGION"] = "eu-west-2"


@pytest.fixture
def secretsmanager_client(aws_creds):
    with mock_aws():
        secretsmanager = boto3.client("secretsmanager")
        yield secretsmanager


def test_create_secret(secretsmanager_client):
    secret_name = "test"
    username = "username"
    password = "password"
    result = create_secret(secret_name, username, password)
    assert list_secrets() == ["test"]  # use secret manager to find the secrte
    assert result == f"{secret_name} has been stored successfully"


def test_create_secret_duplicate(secretsmanager_client):
    secret_name = "test"
    username = "username"
    password = "password"
    result = create_secret(secret_name, username, password)
    secret_name = "test"
    username = "username"
    password = "password"
    result = create_secret(secret_name, username, password)
    assert result == f"{secret_name} already exists."


def test_get_secret(secretsmanager_client):
    secret_name = "test"
    username = "username"
    password = "password"
    create_secret(secret_name, username, password)
    result = get_secret(secret_name)
    assert result == f"{secret_name} has been stored in a file successfully"


def test_get_secret_non_existant_secret(secretsmanager_client):
    secret_name = "test"
    username = "username"
    password = "password"
    create_secret(secret_name, username, password)
    result = get_secret("john")
    assert result == "john was not found."


def test_list_secrets(secretsmanager_client):
    secret_name = "test1"
    username = "username1"
    password = "password1"
    create_secret(secret_name, username, password)
    secret_name = "test2"
    username = "username2"
    password = "password2"
    create_secret(secret_name, username, password)
    result = list_secrets()
    assert result == ["test1", "test2"]


def test_delete_secret(secretsmanager_client):
    secret_name = "test"
    username = "username"
    password = "password"
    create_secret(secret_name, username, password)
    result = delete_secret(secret_name)
    assert result == f"{secret_name} has been successfully deleted!"
    assert list_secrets() == []


def test_random_password(secretsmanager_client):
    result = random_password()
    assert len(result) == 64
    assert isinstance(result, str)
