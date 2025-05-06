# CurlClient

A powerful C++ HTTP client library that wraps libcurl with additional features for modern applications.

## Features

- **Complete HTTP Support**: GET, POST, PUT, DELETE, PATCH methods with various payload types
- **Cookie Management**: Automatic handling of cookies between requests
- **Header Management**: Easily set default and per-request headers
- **JSON Integration**: Native support for JSON requests and responses using nlohmann/json
- **Proxy Support**: Configure proxies for your requests
- **SSL Options**: Control SSL verification settings
- **Redirect Handling**: Configure automatic following of HTTP redirects
- **Retry Mechanism**: Configurable retry strategies for failed requests
- **Thread Safety**: Operations are protected with mutexes for concurrent usage
- **Modern C++**: Uses modern C++ features including move semantics

## Requirements

- C++11 or later
- [libcurl](https://curl.se/libcurl/)
- [nlohmann/json](https://github.com/nlohmann/json)

## Usage Examples

### Basic GET Request

```cpp
#include "CurlClient.h"

int main() {
    CurlClient client;
    auto response = client.get("https://api.example.com/data");
    
    if (response.isSuccess()) {
        std::cout << "Response: " << response.body << std::endl;
    } else {
        std::cout << "Error: " << response.status << std::endl;
    }
    
    return 0;
}
```

### POST with JSON

```cpp
#include "CurlClient.h"

int main() {
    CurlClient client;
    
    // Create JSON payload
    json payload = {
        {"name", "John Doe"},
        {"email", "john@example.com"}
    };
    
    auto response = client.post("https://api.example.com/users", payload);
    
    if (response.isSuccess() && response.isJson()) {
        auto jsonResponse = response.json();
        std::cout << "Created user with ID: " << jsonResponse["id"] << std::endl;
    }
    
    return 0;
}
```

### Setting Default Headers

```cpp
#include "CurlClient.h"

int main() {
    CurlClient client;
    
    // Set default headers for all requests
    client.setHeader("Authorization", "Bearer token123")
          .setUserAgent("MyApp/1.0");
    
    // Make a request with the default headers
    auto response = client.get("https://api.example.com/protected-resource");
    
    return 0;
}
```

### Using Cookies

```cpp
#include "CurlClient.h"

int main() {
    CurlClient client;
    
    // Login and get cookies automatically stored
    client.post("https://example.com/login", {
        {"username", "user"},
        {"password", "pass"}
    });
    
    // Subsequent request will use the stored cookies
    auto response = client.get("https://example.com/dashboard");
    
    return 0;
}
```

### Configuring Retry Strategy

```cpp
#include "CurlClient.h"
#include "RetryStrategy.h"

int main() {
    CurlClient client;
    
    // Create a custom retry strategy
    auto retryStrategy = std::make_shared<RetryStrategy>(
        5,                        // Maximum 5 retry attempts
        1.0,                      // Backoff factor
        std::set<int>{429, 500, 502, 503, 504}, // Status codes to retry
        true,                     // Retry on connection errors
        true                      // Add jitter to backoff times
    );
    
    // Set as default for all client requests
    client.setRetryStrategy(retryStrategy);
    
    // Make a request that will use the retry strategy
    auto response = client.get("https://api.example.com/flaky-endpoint");
    
    std::cout << "Request was retried " << response.retryCount << " times" << std::endl;
    
    return 0;
}
```

## API Reference

### Constructor and Configuration

- `CurlClient()`: Create a new client with default settings
- `setTimeout(int timeout)`: Set timeout in seconds for all requests
- `setHeader(const std::string& name, const std::string& value)`: Set a default header
- `setHeaders(const headers& headers)`: Set multiple default headers
- `setUserAgent(const std::string& userAgent)`: Set the user agent
- `setProxy(const std::string& proxy)`: Set a proxy server
- `setDisableRedirect(bool disable)`: Configure redirect following
- `setInsecureSkipVerify(bool skip)`: Configure SSL verification
- `setMaxRedirect(int maxRedirect)`: Set maximum redirects to follow
- `setRetryStrategy(std::shared_ptr<RetryStrategy> strategy)`: Set retry strategy

### HTTP Methods

- `get(const std::string& url, ...)`: Perform GET request
- `post(const std::string& url, ...)`: Perform POST request
- `put(const std::string& url, ...)`: Perform PUT request
- `del(const std::string& url, ...)`: Perform DELETE request
- `patch(const std::string& url, ...)`: Perform PATCH request

Each method has overloads for different payload types:
- Empty payload
- String payload with content type
- Form data as key-value pairs
- JSON objects

### Response Object

The Response object contains:
- `int status`: HTTP status code
- `std::string body`: Response body
- `headers`: Map of response headers
- `std::string finalUrl`: Final URL after redirects
- `std::unordered_map<std::string, Cookie> cookies`: Cookies from response
- `int retryCount`: Number of retries performed for this request
- `isSuccess()`: Check if status is 2xx
- `isJson()`: Check if body is valid JSON
- `json()`: Parse body as JSON
- `hasHeader(const std::string& name)`: Check if header exists
- `getHeader(const std::string& name)`: Get header value

### RetryStrategy

The RetryStrategy class configures how request retries are handled:

- `RetryStrategy(int total, double backoff_factor, const std::set<int>& status_forcelist, bool retry_on_connection_error, bool add_jitter)`: Create a retry strategy with custom settings
  - `total`: Maximum number of retry attempts (default: 3)
  - `backoff_factor`: Factor to apply to backoff timing (default: 0.5)
  - `status_forcelist`: HTTP status codes that should trigger a retry (default: {429, 500, 502, 503, 504})
  - `retry_on_connection_error`: Whether to retry on connection errors (default: true)
  - `add_jitter`: Whether to add random jitter to backoff times (default: true)
