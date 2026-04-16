import requests

# Test local server
base_url = "http://localhost:8000"


def test_api():
    # Test health check
    response = requests.get(f"{base_url}/api/health")
    print("Health check:", response.json())

    # Test login
    login_data = {"username": "admin", "password": "admin"}
    response = requests.post(f"{base_url}/api/auth/login", json=login_data)
    print("Login:", response.json())

    # Test products
    response = requests.get(f"{base_url}/api/products")
    print("Products:", response.json())


if __name__ == "__main__":
    test_api()