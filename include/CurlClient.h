#pragma once

#ifndef Curl_H
#define Curl_H

#include <string>
#include <unordered_map>
#include <memory>
#include <vector>
#include <mutex>
#include <nlohmann/json.hpp>
#include <chrono>
#include <set>
#include <random>
#include <functional>
#include <curl/curl.h>
#include <RetryStrategy.h>
// For convenience
using json = nlohmann::json;

/**
 * @class CurlClient
 * @brief A HTTP client that handles cookies, caches responses, and manages memory.
 *
 * This class provides a wrapper around the libcurl library, offering:
 * - Automatic cookie handling between requests
 * - Response caching based on URL
 * - Proper memory management with RAII principles
 * - Thread-safe operations
 * - Convenient setter methods for request parameters
 * - JSON request/response support
 * - Configurable retry mechanism
 */
class CurlClient {
public:
	// Type aliases for convenience
	using headers = std::unordered_map<std::string, std::string>;

	/**
	 * @brief Constructs a new CurlClient with default settings.
	 */
	CurlClient();

	/**
	 * @brief Destroys the CurlClient and frees all allocated resources.
	 */
	~CurlClient();

	// Prevent copying
	CurlClient(const CurlClient&) = delete;
	CurlClient& operator=(const CurlClient&) = delete;

	// Allow moving
	CurlClient(CurlClient&& other) noexcept;
	CurlClient& operator=(CurlClient&& other) noexcept;

	/**
	 * @brief Structure to hold cookie data with all attributes
	 */
	struct Cookie {
		std::string name;
		std::string value;
		std::string domain;
		std::string path = "/";
		std::chrono::system_clock::time_point expires;
		int maxAge = 0;  // Same semantics as the Go cookie: 0 means no 'Max-Age' attribute
		bool httpOnly = false;
		bool secure = false;
		int sameSite = 0;  // 0=None, 1=Lax, 2=Strict, 3=Default

		// Convert to string value for backward compatibility
		operator std::string() const {
			return value;
		}
	};

	/**
	 * @brief Structure to hold request parameters
	 */
	struct RequestParams {
		std::string url;
		std::string method = "GET";
		std::string body;
		std::string userAgent;
		std::string proxy;
		CurlClient::headers headers;
		int timeout = 30;
		bool disableRedirect = false;
		bool insecureSkipVerify = false;
		bool forceHTTP1 = true;
		int maxRedirect = 10; // Maximum number of redirects to follow (default: 10)
		RetryStrategy* retryStrategy = nullptr; // Optional retry strategy for this specific request
		bool withoutDefaultHeader = false;
	};

	/**
	 * @brief Response structure with ownership of memory resources
	 */
	struct Response {
		int status = 0;
		std::string body;
		CurlClient::headers headers;
		std::string finalUrl;
		std::string requestId;
		std::string rawHeaders;
		int retryCount = 0; // Number of retries that were performed
		int redirectCount = 0; // Number of redirects that were followed
		std::unordered_map<std::string, Cookie> cookies;

		/**
		 * @brief Parse the response body as JSON
		 *
		 * @return json JSON object parsed from body
		 * @throws nlohmann::json::parse_error if the body is not valid JSON
		 */
		json json() const {
			return nlohmann::json::parse(body);
		}

		/**
		 * @brief Check if response was successful (status 200-299)
		 *
		 * @return true if status is in the 200-299 range
		 */
		bool isSuccess() const {
			return status >= 200 && status < 300;
		}

		/**
		 * @brief Check if response body is valid JSON
		 *
		 * @return true if the body contains valid JSON
		 */
		bool [[nodiscard]] isJson() const {
			try {
				auto value = nlohmann::json::parse(body);
				return true;
			}
			catch (const nlohmann::json::parse_error&) {
			}
			return false;
		}

		/**
		 * @brief Check if response has a specific header
		 *
		 * @param headerName Name of the header to check
		 * @return true if header exists
		 */
		bool hasHeader(const std::string& headerName) const;

		/**
		 * @brief Get value of a specific header
		 *
		 * @param headerName Name of the header to retrieve
		 * @return std::string Header value or empty string if not found
		 */
		std::string getHeader(const std::string& headerName) const;
	};

	/**
	 * @brief Sets the timeout value for all requests
	 *
	 * @param timeout Timeout in seconds
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setTimeout(int timeout);

	/**
	 * @brief Sets a single header for all requests
	 *
	 * @param name Header name
	 * @param value Header value
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setHeader(const std::string& name, const std::string& value);

	/**
	 * @brief Removes a header from default headers
	 *
	 * @param name Header name to remove
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& removeHeader(const std::string& name);

	/**
	 * @brief Sets multiple headers for all requests
	 *
	 * @param headers Map of header names to values
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setHeaders(const CurlClient::headers& headers);

	/**
	 * @brief Sets the user agent for all requests
	 *
	 * @param userAgent User agent string
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setUserAgent(const std::string& userAgent);

	/**
	 * @brief Sets the proxy for all requests
	 *
	 * @param proxy Proxy URL (e.g., "http://proxy:8080")
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setProxy(const std::string& proxy);

	/**
	 * @brief Sets whether to follow redirects for all requests
	 *
	 * @param disable True to disable redirect following, false to enable
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setDisableRedirect(bool disable);

	/**
	 * @brief Sets whether to skip SSL verification for all requests
	 *
	 * @param skip True to skip verification, false otherwise
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setInsecureSkipVerify(bool skip);

	/**
	 * @brief Sets whether to force HTTP/1 for all requests
	 *
	 * @param force True to force HTTP/1, false otherwise
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setForceHTTP1(bool force);

	/**
	 * @brief Sets the maximum number of redirects to follow for all requests
	 *
	 * @param maxRedirect Maximum number of redirects (0 to disable following redirects)
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setMaxRedirect(int maxRedirect);

	/**
	 * @brief Sets the default retry strategy for all requests
	 *
	 * @param strategy Pointer to a RetryStrategy object (nullptr to disable retries)
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setRetryStrategy(std::shared_ptr<RetryStrategy> strategy);

	/**
	 * @brief Sets a callback to be called after each request is executed
	 *
	 * @param callback The callback function taking (const RequestParams&, const Response&)
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& setRequestCallback(std::function<void(const RequestParams&, const Response&)> callback);

	/**
	 * @brief Sets a callback function that will be called before each request
	 * @param callback Function that takes RequestParams by reference and can modify it
	 * @return Reference to this CurlClient instance for method chaining
	 */
	CurlClient& setRequestCallbackBefore(std::function<void(RequestParams&)> callback);

	/**
	 * @brief Makes a simple GET request
	 *
	 * @param url URL to request
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response get(const std::string& url, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a GET request with a body
	 *
	 * @param url URL to request
	 * @param body Request body
	 * @param contentType Content-Type header value
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response get(const std::string& url, const std::string& body, const std::string contentType = "application/x-www-form-urlencoded", const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a GET request with form data
	 *
	 * @param url URL to request
	 * @param formData Form data to send
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response get(const std::string& url, const std::unordered_map<std::string, std::string>& formData, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a GET request with JSON body
	 *
	 * @param url URL to request
	 * @param jsonBody JSON body to send
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response get(const std::string& url, const json& jsonBody, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a GET request and parses response as JSON
	 *
	 * @param url URL to request
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return json JSON parsed from response
	 * @throws std::runtime_error if request fails or response is not valid JSON
	 */
	json getJson(const std::string& url, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a simple POST request
	 *
	 * @param url URL to request
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response post(const std::string& url, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a POST request with string body
	 *
	 * @param url URL to request
	 * @param body Request body
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response post(const std::string& url, const std::string& body, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a POST request with body and content type
	 *
	 * @param url URL to request
	 * @param body Request body
	 * @param contentType Content-Type header value
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response post(const std::string& url, const std::string& body, const std::string contentType = "application/x-www-form-urlencoded", const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a POST request with form data
	 *
	 * @param url URL to request
	 * @param formData Form data to send
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response post(const std::string& url, const std::unordered_map<std::string, std::string>& formData, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a POST request with JSON body
	 *
	 * @param url URL to request
	 * @param jsonBody JSON body to send
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response post(const std::string& url, const json& jsonBody, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a simple PUT request
	 *
	 * @param url URL to request
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response put(const std::string& url, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a PUT request with string body
	 *
	 * @param url URL to request
	 * @param body Request body
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response put(const std::string& url, const std::string& body, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a PUT request with body and content type
	 *
	 * @param url URL to request
	 * @param body Request body
	 * @param contentType Content-Type header value
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response put(const std::string& url, const std::string& body, const std::string& contentType, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a PUT request with JSON body
	 *
	 * @param url URL to request
	 * @param jsonBody JSON body to send
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response put(const std::string& url, const json& jsonBody, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a DELETE request
	 *
	 * @param url URL to request
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response del(const std::string& url, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Makes a PATCH request with JSON body
	 *
	 * @param url URL to request
	 * @param jsonBody JSON body to send
	 * @param headers Additional headers to send
	 * @param withoutDefaultHeader Whether to exclude default headers
	 * @return Response HTTP response
	 */
	Response patch(const std::string& url, const json& jsonBody, const CurlClient::headers& headers = {}, bool withoutDefaultHeader = false);

	/**
	 * @brief Sends a HTTP request with given parameters
	 *
	 * @param params Request parameters
	 * @return Response HTTP response
	 */
	Response sendRequest(const RequestParams& params);

	/**
	 * @brief Clears all cookies
	 *
	 * @return CurlClient& Reference to this client for method chaining
	 */
	CurlClient& clearCookies();

	/**
	 * @brief Gets all cookies as a string
	 *
	 * @return std::string Cookies formatted as a string
	 */
	std::string getCookiesAsString() const;

	/**
	 * @brief Gets all current cookies
	 *
	 * @return std::vector<Cookie> Vector of cookies
	 */
	std::vector<Cookie> getCookies() const;

	/**
	 * @brief Adds a cookie
	 *
	 * @param name Cookie name
	 * @param value Cookie value
	 * @param domain Cookie domain
	 */
	void addCookie(const std::string& name, const std::string& value, const std::string& domain = "");

	/**
	 * @brief Encodes a string for use in a URL
	 *
	 * @param str String to encode
	 * @return std::string URL-encoded string
	 */
	static std::string urlEncode(const std::string& str);

private:
	CURL* m_curl;
	struct curl_slist* m_headerList;
	RequestParams m_defaultParams;
	CurlClient::headers m_defaultHeaders;
	std::unordered_map<std::string, Cookie> m_cookies;
	std::shared_ptr<RetryStrategy> m_retryStrategy;

	std::function<void(const RequestParams&, const Response&)> m_requestCallback;
	std::function<void(RequestParams&)> m_requestCallbackBefore;

	// Mutex for thread safety
	std::mutex m_mutex;

	/**
	 * @brief Updates cookies from response headers
	 *
	 * @param headers Headers containing Set-Cookie
	 * @param targetMap Map to store cookies in
	 * @param checkExpired Whether to check if cookies are expired
	 */
	void updateCookies(const std::string& headers, std::unordered_map<std::string, Cookie>& targetMap, bool checkExpired = true);

	/**
	 * @brief Processes cookie JSON object
	 *
	 * @param cookieJson JSON object containing cookie data
	 * @param targetMap Map to store cookies in
	 * @param checkExpired Whether to check if cookies are expired
	 */
	void processCookieJson(const json& cookieJson, std::unordered_map<std::string, Cookie>& targetMap, bool checkExpired);

	/**
	 * @brief Parses a single cookie header
	 *
	 * @param cookieHeader Set-Cookie header value
	 * @param targetMap Map to store cookies in
	 * @param checkExpired Whether to check if cookies are expired
	 */
	void parseSingleCookieHeader(const std::string& cookieHeader, std::unordered_map<std::string, Cookie>& targetMap, bool checkExpired);

	/**
	 * @brief Parses cookie attributes
	 *
	 * @param attributesStr Cookie attributes string
	 * @param cookie Cookie object to update
	 */
	void parseAttributeString(const std::string& attributesStr, Cookie& cookie);

	/**
	 * @brief Merges default parameters with request-specific parameters
	 *
	 * @param params The request-specific parameters
	 * @return RequestParams The merged parameters
	 */
	RequestParams mergeWithDefaults(const RequestParams& params) const;

	/**
	 * @brief Parses a raw headers string into a map of header names and values
	 *
	 * @param headersStr The raw headers string
	 * @param headersMap The map to store parsed headers in
	 */
	void parseHeadersToMap(const std::string& headersStr, CurlClient::headers& headersMap);

	/**
	 * @brief Builds header list for libcurl
	 *
	 * @param headers Headers to include
	 * @return struct curl_slist* Header list for libcurl
	 */
	struct curl_slist* buildCurlHeaders(const CurlClient::headers& headers) const;

	/**
	 * @brief Builds cookies string for libcurl
	 *
	 * @return std::string Formatted cookies string
	 */
	std::string buildCookies() const;

	/**
	 * @brief Callback function for libcurl to write response body
	 *
	 * @param contents Pointer to received data
	 * @param size Size of each data element
	 * @param nmemb Number of data elements
	 * @param userp User pointer (string to append data to)
	 * @return size_t Number of bytes handled
	 */
	static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);

	/**
	 * @brief Callback function for libcurl to write response headers
	 *
	 * @param contents Pointer to received header
	 * @param size Size of each data element
	 * @param nmemb Number of data elements
	 * @param userp User pointer (string to append headers to)
	 * @return size_t Number of bytes handled
	 */
	static size_t headerCallback(void* contents, size_t size, size_t nmemb, void* userp);

	/**
	 * @brief Helper method to handle resource cleanup during destruction or move
	 */
	void cleanup();

	/**
	 * @brief Internal implementation of sendRequest that tracks redirect count
	 *
	 * @param params The request parameters
	 * @param redirectCount Current redirect count
	 * @return Response The HTTP response
	 */
	Response sendRequest(const RequestParams& params, int redirectCount);
};
#endif