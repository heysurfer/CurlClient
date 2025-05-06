#define _CRT_SECURE_NO_WARNINGS

#include <CurlClient.h>
#include <sstream>
#include <regex>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <thread>

// Implementation of Response methods
bool CurlClient::Response::hasHeader(const std::string& headerName) const {
	std::string lowerName = headerName;
	std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
		[](unsigned char c) { return std::tolower(c); });

	for (const auto& pair : headers) {
		std::string lowerKey = pair.first;
		std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(),
			[](unsigned char c) { return std::tolower(c); });

		if (lowerKey == lowerName) {
			return true;
		}
	}

	return false;
}

std::string CurlClient::Response::getHeader(const std::string& headerName) const {
	std::string lowerName = headerName;
	std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
		[](unsigned char c) { return std::tolower(c); });

	for (const auto& pair : headers) {
		std::string lowerKey = pair.first;
		std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(),
			[](unsigned char c) { return std::tolower(c); });

		if (lowerKey == lowerName) {
			return pair.second;
		}
	}

	return "";
}

// Static callback functions for libcurl
size_t CurlClient::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t realSize = size * nmemb;
	std::string* str = static_cast<std::string*>(userp);
	str->append(static_cast<char*>(contents), realSize);
	return realSize;
}

size_t CurlClient::headerCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t realSize = size * nmemb;
	std::string* str = static_cast<std::string*>(userp);
	str->append(static_cast<char*>(contents), realSize);
	return realSize;
}

// CurlClient implementation
CurlClient::CurlClient()
	: m_curl(nullptr), m_headerList(nullptr), m_retryStrategy(nullptr) {
	curl_global_init(CURL_GLOBAL_ALL);
	m_curl = curl_easy_init();
	if (!m_curl) {
		throw std::runtime_error("Failed to initialize libcurl");
	}

	// Set default parameters
	m_defaultParams.method = "GET";
	m_defaultParams.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
	m_defaultParams.timeout = 30;
	m_defaultParams.disableRedirect = false;
	m_defaultParams.insecureSkipVerify = false;
	m_defaultParams.forceHTTP1 = false;
	m_defaultParams.maxRedirect = 10;
}

CurlClient::~CurlClient() {
	cleanup();
	curl_global_cleanup();
}

CurlClient::CurlClient(CurlClient&& other) noexcept
	: m_curl(nullptr), m_headerList(nullptr) {
	m_curl = other.m_curl;
	m_headerList = other.m_headerList;
	m_cookies = std::move(other.m_cookies);
	m_defaultHeaders = std::move(other.m_defaultHeaders);
	m_defaultParams = std::move(other.m_defaultParams);
	m_retryStrategy = std::move(other.m_retryStrategy);
	m_requestCallback = std::move(other.m_requestCallback);
	m_requestCallbackBefore = std::move(other.m_requestCallbackBefore);

	other.m_curl = nullptr;
	other.m_headerList = nullptr;
}

CurlClient& CurlClient::operator=(CurlClient&& other) noexcept {
	if (this != &other) {
		cleanup();

		m_curl = other.m_curl;
		m_headerList = other.m_headerList;
		m_cookies = std::move(other.m_cookies);
		m_defaultHeaders = std::move(other.m_defaultHeaders);
		m_defaultParams = std::move(other.m_defaultParams);
		m_retryStrategy = std::move(other.m_retryStrategy);
		m_requestCallback = std::move(other.m_requestCallback);
		m_requestCallbackBefore = std::move(other.m_requestCallbackBefore);

		other.m_curl = nullptr;
		other.m_headerList = nullptr;
	}
	return *this;
}

void CurlClient::cleanup() {
	if (m_headerList) {
		curl_slist_free_all(m_headerList);
		m_headerList = nullptr;
	}

	if (m_curl) {
		curl_easy_cleanup(m_curl);
		m_curl = nullptr;
	}
}

CurlClient& CurlClient::setTimeout(int timeout) {
	m_defaultParams.timeout = timeout;
	return *this;
}

CurlClient& CurlClient::setHeader(const std::string& name, const std::string& value) {
	m_defaultHeaders[name] = value;
	return *this;
}

CurlClient& CurlClient::removeHeader(const std::string& name) {
	m_defaultHeaders.erase(name);
	return *this;
}

CurlClient& CurlClient::setHeaders(const CurlClient::headers& headers) {
	for (const auto& header : headers) {
		m_defaultHeaders[header.first] = header.second;
	}
	return *this;
}

CurlClient& CurlClient::setUserAgent(const std::string& userAgent) {
	m_defaultParams.userAgent = userAgent;
	return *this;
}

CurlClient& CurlClient::setProxy(const std::string& proxy) {
	m_defaultParams.proxy = proxy;
	return *this;
}

CurlClient& CurlClient::setDisableRedirect(bool disable) {
	m_defaultParams.disableRedirect = disable;
	return *this;
}

CurlClient& CurlClient::setInsecureSkipVerify(bool skip) {
	m_defaultParams.insecureSkipVerify = skip;
	return *this;
}

CurlClient& CurlClient::setForceHTTP1(bool force) {
	m_defaultParams.forceHTTP1 = force;
	return *this;
}

CurlClient& CurlClient::setMaxRedirect(int maxRedirect) {
	m_defaultParams.maxRedirect = maxRedirect;
	// If maxRedirect is 0, also disable redirects entirely
	if (maxRedirect == 0) {
		m_defaultParams.disableRedirect = true;
	}
	return *this;
}

CurlClient& CurlClient::setRetryStrategy(std::shared_ptr<RetryStrategy> strategy) {
	m_retryStrategy = strategy;
	return *this;
}

CurlClient& CurlClient::setRequestCallback(std::function<void(const RequestParams&, const Response&)> callback) {
	m_requestCallback = callback;
	return *this;
}

CurlClient& CurlClient::setRequestCallbackBefore(std::function<void(RequestParams&)> callback) {
	m_requestCallbackBefore = callback;
	return *this;
}

std::string CurlClient::urlEncode(const std::string& str) {
	CURL* curl = curl_easy_init();
	if (!curl) {
		throw std::runtime_error("Failed to initialize curl for URL encoding");
	}

	char* output = curl_easy_escape(curl, str.c_str(), static_cast<int>(str.length()));
	if (!output) {
		curl_easy_cleanup(curl);
		throw std::runtime_error("Failed to URL encode string");
	}

	std::string result(output);
	curl_free(output);
	curl_easy_cleanup(curl);

	return result;
}

struct curl_slist* CurlClient::buildCurlHeaders(const CurlClient::headers& headers) const {
	struct curl_slist* headerList = nullptr;

	for (const auto& header : headers) {
		std::string headerStr = header.first + ": " + header.second;
		headerList = curl_slist_append(headerList, headerStr.c_str());
	}

	return headerList;
}

std::string CurlClient::buildCookies() const {
	std::stringstream cookieStr;
	auto now = std::chrono::system_clock::now();
	bool first = true;

	for (const auto& [name, cookie] : m_cookies) {
		if (cookie.expires != std::chrono::system_clock::time_point() && cookie.expires <= now) {
			continue;
		}

		if (!first) {
			cookieStr << "; ";
		}

		cookieStr << cookie.name << "=" << cookie.value;
		first = false;
	}

	return cookieStr.str();
}

CurlClient::RequestParams CurlClient::mergeWithDefaults(const RequestParams& params) const {
	RequestParams merged = m_defaultParams;

	merged.url = params.url;
	merged.method = params.method;
	if (!params.body.empty()) merged.body = params.body;
	if (!params.userAgent.empty()) merged.userAgent = params.userAgent;
	if (!params.proxy.empty()) merged.proxy = params.proxy;

	merged.headers = m_defaultHeaders;
	for (const auto& header : params.headers) {
		merged.headers[header.first] = header.second;
	}

	if (params.timeout != 30) merged.timeout = params.timeout;
	if (params.disableRedirect != false) merged.disableRedirect = params.disableRedirect;
	if (params.insecureSkipVerify != false) merged.insecureSkipVerify = params.insecureSkipVerify;
	if (params.forceHTTP1 != false) merged.forceHTTP1 = params.forceHTTP1;
	if (params.maxRedirect != 10) merged.maxRedirect = params.maxRedirect;

	// Use request-specific retry strategy if provided
	if (params.retryStrategy != nullptr) {
		merged.retryStrategy = params.retryStrategy;
	}

	return merged;
}

CurlClient::Response CurlClient::sendRequest(const RequestParams& params) {
	return sendRequest(params, 0);
}

CurlClient::Response CurlClient::sendRequest(const RequestParams& params, int redirectCount) {
	// Thread safety for curl handle
	std::lock_guard<std::mutex> lock(m_mutex);

	// Merge default params with request params
	RequestParams mergedParams = mergeWithDefaults(params);

	// Call the before request callback if set
	if (m_requestCallbackBefore) {
		m_requestCallbackBefore(mergedParams);
	}

	// Determine which retry strategy to use - request-specific or default
	RetryStrategy* retryStrategy = mergedParams.retryStrategy ? mergedParams.retryStrategy : m_retryStrategy.get();
	int maxRetries = retryStrategy ? retryStrategy->get_total() : 0;
	int currentRetry = 0;
	Response response;

	while (true) {
		// Reset CURL handle for this request
		curl_easy_reset(m_curl);

		// Free any existing header list
		if (m_headerList) {
			curl_slist_free_all(m_headerList);
			m_headerList = nullptr;
		}

		// Prepare headers
		CurlClient::headers requestHeaders;
		if (params.withoutDefaultHeader) {
			requestHeaders = params.headers;
		}
		else {
			requestHeaders = mergedParams.headers;
		}

		m_headerList = buildCurlHeaders(requestHeaders);

		// Set up the response data structures
		std::string responseBody;
		std::string responseHeaders;

		// Set common options
		curl_easy_setopt(m_curl, CURLOPT_URL, mergedParams.url.c_str());
		curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, writeCallback);
		curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &responseBody);
		curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, headerCallback);
		curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, &responseHeaders);
		curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, mergedParams.timeout);

		// Set SSL verification options
		if (mergedParams.insecureSkipVerify) {
			curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		// Set user agent
		if (!mergedParams.userAgent.empty()) {
			curl_easy_setopt(m_curl, CURLOPT_USERAGENT, mergedParams.userAgent.c_str());
		}

		// Set proxy
		if (!mergedParams.proxy.empty()) {
			curl_easy_setopt(m_curl, CURLOPT_PROXY, mergedParams.proxy.c_str());
		}

		// Set redirect behavior
		if (mergedParams.disableRedirect) {
			curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 0L);
		}
		else {
			curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L);
			curl_easy_setopt(m_curl, CURLOPT_MAXREDIRS, mergedParams.maxRedirect);
		}

		// Force HTTP/1 if requested
		if (mergedParams.forceHTTP1) {
			curl_easy_setopt(m_curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
		}

		// Set request method
		if (mergedParams.method == "GET") {
			curl_easy_setopt(m_curl, CURLOPT_HTTPGET, 1L);
		}
		else if (mergedParams.method == "POST") {
			curl_easy_setopt(m_curl, CURLOPT_POST, 1L);
			if (!mergedParams.body.empty()) {
				curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, mergedParams.body.c_str());
				curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, mergedParams.body.length());
			}
		}
		else if (mergedParams.method == "PUT" || mergedParams.method == "DELETE" || mergedParams.method == "PATCH") {
			curl_easy_setopt(m_curl, CURLOPT_CUSTOMREQUEST, mergedParams.method.c_str());
			if (!mergedParams.body.empty()) {
				curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, mergedParams.body.c_str());
				curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE, mergedParams.body.length());
			}
		}

		// Set headers
		if (m_headerList) {
			curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, m_headerList);
		}

		// Set cookies
		std::string cookies = buildCookies();
		if (!cookies.empty()) {
			curl_easy_setopt(m_curl, CURLOPT_COOKIE, cookies.c_str());
		}

		// Perform the request
		CURLcode res = curl_easy_perform(m_curl);

		response.retryCount = currentRetry;
		response.redirectCount = redirectCount;
		response.body = responseBody;
		response.rawHeaders = responseHeaders;

		if (res != CURLE_OK) {
			response.status = 0;
		}
		else {
			// Get response code
			long httpCode = 0;
			curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &httpCode);
			response.status = static_cast<int>(httpCode);

			// Get final URL after possible redirects
			char* finalUrl = nullptr;
			curl_easy_getinfo(m_curl, CURLINFO_EFFECTIVE_URL, &finalUrl);
			if (finalUrl) {
				response.finalUrl = finalUrl;
			}
		}

		// Parse headers and update cookies
		parseHeadersToMap(response.rawHeaders, response.headers);
		updateCookies(response.rawHeaders, m_cookies, true);
		updateCookies(response.rawHeaders, response.cookies, false);

		// Handle manual redirects
		if (!mergedParams.disableRedirect && (response.status == 301 || response.status == 302 || response.status == 303 || response.status == 307 || response.status == 308)) {
			if (redirectCount >= mergedParams.maxRedirect) {
				// Max redirects reached, return the response as is
				break;
			}

			std::string location = response.getHeader("location");
			if (!location.empty()) {
				RequestParams redirectParams = params;

				// Handle relative URLs
				if (location[0] == '/') {
					// Relative to domain root
					std::string baseUrl = mergedParams.url;
					size_t domainEndPos = baseUrl.find('/', baseUrl.find("://") + 3);
					if (domainEndPos != std::string::npos) {
						baseUrl = baseUrl.substr(0, domainEndPos);
					}
					location = baseUrl + location;
				}
				else if (location.find("://") == std::string::npos) {
					// Relative to current path
					std::string baseUrl = mergedParams.url;
					size_t lastSlashPos = baseUrl.find_last_of('/');
					if (lastSlashPos != std::string::npos && lastSlashPos > 8) { // 8 to skip http(s)://
						baseUrl = baseUrl.substr(0, lastSlashPos + 1);
						location = baseUrl + location;
					}
				}

				redirectParams.url = location;

				// For 303, always convert to GET
				if (response.status == 303) {
					redirectParams.method = "GET";
					redirectParams.body = "";
				}

				return sendRequest(redirectParams, redirectCount + 1);
			}
		}

		bool shouldRetry = false;
		if (retryStrategy && currentRetry < maxRetries) {
			if (retryStrategy->should_retry(response.status) || (res != CURLE_OK && retryStrategy->retry_on_connection_error())) {
				shouldRetry = true;
			}
		}

		if (!shouldRetry) {
			break;
		}

		// Calculate backoff time and sleep
		if (retryStrategy) {
			std::chrono::milliseconds backoffTime = retryStrategy->get_backoff_time(currentRetry);
			std::this_thread::sleep_for(backoffTime);
		}

		currentRetry++;
	}

	// Call the request callback if set
	if (m_requestCallback) {
		m_requestCallback(params, response);
	}

	return response;
}

CurlClient::Response CurlClient::get(const std::string& url, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	RequestParams params;
	params.url = url;
	params.method = "GET";
	params.headers = headers;
	params.withoutDefaultHeader = withoutDefaultHeader;
	return sendRequest(params);
}

CurlClient::Response CurlClient::get(const std::string& url, const std::string& body, const std::string contentType, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	RequestParams params;
	params.url = url;
	params.method = "GET";
	params.body = body;
	params.headers = headers;
	params.withoutDefaultHeader = withoutDefaultHeader;

	if (!contentType.empty()) {
		params.headers["Content-Type"] = contentType;
	}

	return sendRequest(params);
}

CurlClient::Response CurlClient::get(const std::string& url, const std::unordered_map<std::string, std::string>& formData, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	std::stringstream body;
	bool first = true;

	for (const auto& pair : formData) {
		if (!first) {
			body << "&";
		}
		body << urlEncode(pair.first) << "=" << urlEncode(pair.second);
		first = false;
	}

	return get(url, body.str(), "application/x-www-form-urlencoded", headers, withoutDefaultHeader);
}

CurlClient::Response CurlClient::get(const std::string& url, const json& jsonBody, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	std::string body = jsonBody.dump();
	return get(url, body, "application/json", headers, withoutDefaultHeader);
}

json CurlClient::getJson(const std::string& url, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	Response response = get(url, headers, withoutDefaultHeader);

	if (!response.isSuccess()) {
		throw std::runtime_error("HTTP request failed with status code: " + std::to_string(response.status));
	}

	try {
		return response.json();
	}
	catch (const nlohmann::json::parse_error& e) {
		throw std::runtime_error("Failed to parse JSON response: " + std::string(e.what()));
	}
}

CurlClient::Response CurlClient::post(const std::string& url, bool withoutDefaultHeader) {
	RequestParams params;
	params.url = url;
	params.method = "POST";
	params.withoutDefaultHeader = withoutDefaultHeader;
	return sendRequest(params);
}

CurlClient::Response CurlClient::post(const std::string& url, const std::string& body, bool withoutDefaultHeader) {
	return post(url, body, "application/x-www-form-urlencoded", {}, withoutDefaultHeader);
}

CurlClient::Response CurlClient::post(const std::string& url, const std::string& body, const std::string contentType, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	RequestParams params;
	params.url = url;
	params.method = "POST";
	params.body = body;
	params.headers = headers;
	params.withoutDefaultHeader = withoutDefaultHeader;

	if (!contentType.empty()) {
		params.headers["Content-Type"] = contentType;
	}

	return sendRequest(params);
}

CurlClient::Response CurlClient::post(const std::string& url, const std::unordered_map<std::string, std::string>& formData, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	std::stringstream body;
	bool first = true;

	for (const auto& pair : formData) {
		if (!first) {
			body << "&";
		}
		body << urlEncode(pair.first) << "=" << urlEncode(pair.second);
		first = false;
	}

	return post(url, body.str(), "application/x-www-form-urlencoded", headers, withoutDefaultHeader);
}

CurlClient::Response CurlClient::post(const std::string& url, const json& jsonBody, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	std::string body = jsonBody.dump();
	return post(url, body, "application/json", headers, withoutDefaultHeader);
}

CurlClient::Response CurlClient::put(const std::string& url, bool withoutDefaultHeader) {
	RequestParams params;
	params.url = url;
	params.method = "PUT";
	params.withoutDefaultHeader = withoutDefaultHeader;
	return sendRequest(params);
}

CurlClient::Response CurlClient::put(const std::string& url, const std::string& body, bool withoutDefaultHeader) {
	return put(url, body, "application/x-www-form-urlencoded", {}, withoutDefaultHeader);
}

CurlClient::Response CurlClient::put(const std::string& url, const std::string& body, const std::string& contentType, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	RequestParams params;
	params.url = url;
	params.method = "PUT";
	params.body = body;
	params.headers = headers;
	params.withoutDefaultHeader = withoutDefaultHeader;

	if (!contentType.empty()) {
		params.headers["Content-Type"] = contentType;
	}

	return sendRequest(params);
}

CurlClient::Response CurlClient::put(const std::string& url, const json& jsonBody, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	std::string body = jsonBody.dump();
	return put(url, body, "application/json", headers, withoutDefaultHeader);
}

CurlClient::Response CurlClient::del(const std::string& url, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	RequestParams params;
	params.url = url;
	params.method = "DELETE";
	params.headers = headers;
	params.withoutDefaultHeader = withoutDefaultHeader;
	return sendRequest(params);
}

CurlClient::Response CurlClient::patch(const std::string& url, const json& jsonBody, const CurlClient::headers& headers, bool withoutDefaultHeader) {
	std::string body = jsonBody.dump();

	RequestParams params;
	params.url = url;
	params.method = "PATCH";
	params.body = body;
	params.headers = headers;
	params.withoutDefaultHeader = withoutDefaultHeader;
	params.headers["Content-Type"] = "application/json";

	return sendRequest(params);
}

CurlClient& CurlClient::clearCookies() {
	m_cookies.clear();
	return *this;
}

std::string CurlClient::getCookiesAsString() const {
	return buildCookies();
}

std::vector<CurlClient::Cookie> CurlClient::getCookies() const {
	std::vector<CurlClient::Cookie> currentCookies;
	auto now = std::chrono::system_clock::now();

	for (const auto& [name, cookie] : m_cookies) {
		if (cookie.expires == std::chrono::system_clock::time_point() || cookie.expires > now) {
			currentCookies.push_back(cookie);
		}
	}

	return currentCookies;
}

void CurlClient::addCookie(const std::string& name, const std::string& value, const std::string& domain) {
	Cookie cookie;
	cookie.name = name;
	cookie.value = value;
	cookie.domain = domain;
	cookie.expires = std::chrono::system_clock::now() + std::chrono::hours(1);
	cookie.maxAge = 3600; // 1 hour
	cookie.httpOnly = false;
	cookie.secure = false;
	cookie.sameSite = 0; // None
	m_cookies[name] = cookie;
}

void CurlClient::updateCookies(const std::string& headers, std::unordered_map<std::string, Cookie>& targetMap, bool checkExpired) {
	if (headers.empty()) {
		return;
	}

	std::istringstream stream(headers);
	std::string line;

	while (std::getline(stream, line)) {
		if (!line.empty() && line.back() == '\r') {
			line.pop_back();
		}

		std::string lineLower = line;
		std::transform(lineLower.begin(), lineLower.end(), lineLower.begin(),
			[](unsigned char c) { return std::tolower(c); });

		size_t cookiePos = lineLower.find("set-cookie:");
		if (cookiePos == 0 || (cookiePos != std::string::npos && lineLower.find_first_not_of(" \t") == cookiePos)) {
			size_t valueStart = line.find(':', cookiePos) + 1;
			if (valueStart != std::string::npos) {
				std::string cookieValue = line.substr(valueStart);
				cookieValue.erase(0, cookieValue.find_first_not_of(" \t"));
				parseSingleCookieHeader(cookieValue, targetMap, checkExpired);
			}
		}
	}
}

void CurlClient::parseSingleCookieHeader(const std::string& cookieHeader, std::unordered_map<std::string, Cookie>& targetMap, bool checkExpired) {
	size_t separatorPos = cookieHeader.find(';');

	std::string nameValuePair;
	std::string attributesStr = "";

	if (separatorPos != std::string::npos) {
		nameValuePair = cookieHeader.substr(0, separatorPos);
		attributesStr = cookieHeader.substr(separatorPos);
	}
	else {
		nameValuePair = cookieHeader;
	}

	size_t equalsPos = nameValuePair.find('=');
	if (equalsPos == std::string::npos) {
		return;
	}

	std::string name = nameValuePair.substr(0, equalsPos);
	std::string value = nameValuePair.substr(equalsPos + 1);
	name.erase(0, name.find_first_not_of(" \t"));
	name.erase(name.find_last_not_of(" \t") + 1);

	Cookie cookie;
	cookie.name = name;
	cookie.value = value;
	if (!attributesStr.empty()) {
		parseAttributeString(attributesStr, cookie);
	}

	if (!checkExpired || cookie.expires == std::chrono::system_clock::time_point() || cookie.expires > std::chrono::system_clock::now()) {
		targetMap[name] = cookie;
	}
}

void CurlClient::parseAttributeString(const std::string& attributesStr, Cookie& cookie) {
	std::istringstream attributeStream(attributesStr);
	std::string attribute;
	while (std::getline(attributeStream, attribute, ';')) {
		attribute.erase(0, attribute.find_first_not_of(" \t"));
		attribute.erase(attribute.find_last_not_of(" \t") + 1);

		if (attribute.empty()) {
			continue;
		}
		std::string attributeLower = attribute;
		std::transform(attributeLower.begin(), attributeLower.end(), attributeLower.begin(),
			[](unsigned char c) { return std::tolower(c); });

		if (attributeLower == "secure") {
			cookie.secure = true;
		}
		else if (attributeLower == "httponly") {
			cookie.httpOnly = true;
		}
		else {
			size_t equalsPos = attribute.find('=');
			if (equalsPos != std::string::npos) {
				std::string attrName = attribute.substr(0, equalsPos);
				std::string attrValue = attribute.substr(equalsPos + 1);
				attrName.erase(0, attrName.find_first_not_of(" \t"));
				attrName.erase(attrName.find_last_not_of(" \t") + 1);
				attrValue.erase(0, attrValue.find_first_not_of(" \t"));
				attrValue.erase(attrValue.find_last_not_of(" \t") + 1);
				std::string attrNameLower = attrName;
				std::transform(attrNameLower.begin(), attrNameLower.end(), attrNameLower.begin(),
					[](unsigned char c) { return std::tolower(c); });

				if (attrNameLower == "domain") {
					cookie.domain = attrValue;
				}
				else if (attrNameLower == "path") {
					cookie.path = attrValue;
				}
				else if (attrNameLower == "expires") {
					std::tm tm = {};
					std::string expiresStr = attrValue;
					const char* formats[] = {
						"%a, %d %b %Y %H:%M:%S GMT",
						"%A, %d-%b-%y %H:%M:%S GMT",
						"%a %b %d %H:%M:%S %Y",
						"%Y-%m-%dT%H:%M:%SZ"
					};

					bool parsed = false;
					for (const char* format : formats) {
						std::istringstream ss(expiresStr);
						ss >> std::get_time(&tm, format);
						if (!ss.fail()) {
							cookie.expires = std::chrono::system_clock::from_time_t(std::mktime(&tm));
							parsed = true;
							break;
						}
					}
				}
				else if (attrNameLower == "max-age") {
					try {
						int maxAge = std::stoi(attrValue);
						cookie.maxAge = maxAge;

						if (maxAge > 0) {
							cookie.expires = std::chrono::system_clock::now() + std::chrono::seconds(maxAge);
						}
						else if (maxAge <= 0) {
							cookie.expires = std::chrono::system_clock::now() - std::chrono::hours(1);
						}
					}
					catch (const std::exception&) {
					}
				}
				else if (attrNameLower == "samesite") {
					std::string sameSiteValueLower = attrValue;
					std::transform(sameSiteValueLower.begin(), sameSiteValueLower.end(), sameSiteValueLower.begin(),
						[](unsigned char c) { return std::tolower(c); });
					if (sameSiteValueLower == "lax") {
						cookie.sameSite = 1;
					}
					else if (sameSiteValueLower == "strict") {
						cookie.sameSite = 2;
					}
					else if (sameSiteValueLower == "default") {
						cookie.sameSite = 3;
					}
					else {
						cookie.sameSite = 0;
					}
				}
			}
		}
	}
}

void CurlClient::parseHeadersToMap(const std::string& headersStr, CurlClient::headers& headersMap) {
	headersMap.clear();

	std::istringstream stream(headersStr);
	std::string line;
	std::string currentHeader;
	std::string currentValue;

	while (std::getline(stream, line)) {
		if (!line.empty() && line.back() == '\r') {
			line.pop_back();
		}
		if (line.empty()) {
			if (!currentHeader.empty()) {
				headersMap[currentHeader] = currentValue;
				currentHeader.clear();
				currentValue.clear();
			}
			continue;
		}
		if (line[0] == ' ' || line[0] == '\t') {
			if (!currentHeader.empty()) {
				size_t firstNonWS = line.find_first_not_of(" \t");
				if (firstNonWS != std::string::npos) {
					currentValue += ' ' + line.substr(firstNonWS);
				}
			}
			continue;
		}
		if (!currentHeader.empty()) {
			headersMap[currentHeader] = currentValue;
			currentHeader.clear();
			currentValue.clear();
		}

		size_t colonPos = line.find(':');
		if (colonPos != std::string::npos) {
			std::string name = line.substr(0, colonPos);
			std::string value = line.substr(colonPos + 1);

			name.erase(0, name.find_first_not_of(" \t"));
			name.erase(name.find_last_not_of(" \t") + 1);
			value.erase(0, value.find_first_not_of(" \t"));
			value.erase(value.find_last_not_of(" \t") + 1);

			std::string lowerName = name;
			std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(),
				[](unsigned char c) { return std::tolower(c); });

			if (headersMap.find(lowerName) != headersMap.end()) {
				headersMap[lowerName] += ", " + value;
			}
			else {
				currentHeader = lowerName;
				currentValue = value;
			}
		}
	}

	if (!currentHeader.empty()) {
		headersMap[currentHeader] = currentValue;
	}
}

void CurlClient::processCookieJson(const json& cookieJson, std::unordered_map<std::string, Cookie>& targetMap, bool checkExpired) {
	try {
		if (!cookieJson.contains("name") || !cookieJson.contains("value")) {
			return;
		}

		std::string name = cookieJson["name"].get<std::string>();
		std::string value = cookieJson["value"].get<std::string>();

		Cookie cookie;
		cookie.name = name;
		cookie.value = value;

		if (cookieJson.contains("domain")) {
			cookie.domain = cookieJson["domain"].get<std::string>();
		}

		if (cookieJson.contains("path")) {
			cookie.path = cookieJson["path"].get<std::string>();
		}

		if (cookieJson.contains("httpOnly") || cookieJson.contains("http_only")) {
			cookie.httpOnly = cookieJson.contains("httpOnly") ?
				cookieJson["httpOnly"].get<bool>() :
				cookieJson["http_only"].get<bool>();
		}

		if (cookieJson.contains("secure")) {
			cookie.secure = cookieJson["secure"].get<bool>();
		}

		if (cookieJson.contains("maxAge") || cookieJson.contains("max_age")) {
			int maxAge = cookieJson.contains("maxAge") ?
				cookieJson["maxAge"].get<int>() :
				cookieJson["max_age"].get<int>();

			cookie.maxAge = maxAge;
			if (maxAge > 0) {
				cookie.expires = std::chrono::system_clock::now() + std::chrono::seconds(maxAge);
			}
			else if (maxAge <= 0) {
				cookie.expires = std::chrono::system_clock::now() - std::chrono::hours(1);
			}
		}
		if (cookieJson.contains("expires")) {
			std::string expiresStr = cookieJson["expires"].get<std::string>();
			std::tm tm = {};
			const char* formats[] = {
				"%a, %d %b %Y %H:%M:%S GMT",
				"%A, %d-%b-%y %H:%M:%S GMT",
				"%a %b %d %H:%M:%S %Y",
				"%Y-%m-%dT%H:%M:%SZ"
			};

			bool parsed = false;
			for (const char* format : formats) {
				std::istringstream ss(expiresStr);
				ss >> std::get_time(&tm, format);
				if (!ss.fail()) {
					cookie.expires = std::chrono::system_clock::from_time_t(std::mktime(&tm));
					parsed = true;
					break;
				}
			}
		}
		if (cookieJson.contains("sameSite")) {
			std::string sameSiteStr;
			if (cookieJson["sameSite"].is_string()) {
				sameSiteStr = cookieJson["sameSite"].get<std::string>();
				std::transform(sameSiteStr.begin(), sameSiteStr.end(), sameSiteStr.begin(),
					[](unsigned char c) { return std::tolower(c); });
				if (sameSiteStr == "lax") {
					cookie.sameSite = 1;
				}
				else if (sameSiteStr == "strict") {
					cookie.sameSite = 2;
				}
				else if (sameSiteStr == "default") {
					cookie.sameSite = 3;
				}
				else {
					cookie.sameSite = 0;
				}
			}
			else if (cookieJson["sameSite"].is_number()) {
				cookie.sameSite = cookieJson["sameSite"].get<int>();
			}
		}

		if (!checkExpired || cookie.expires == std::chrono::system_clock::time_point() || cookie.expires > std::chrono::system_clock::now()) {
			targetMap[name] = cookie;
		}
	}
	catch (const std::exception&) {
	}
}