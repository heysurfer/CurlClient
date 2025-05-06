#ifndef RETRY_STRATEGY_H
#define RETRY_STRATEGY_H

#include <set>
#include <random>
#include <chrono>

/**
 * @class RetryStrategy
 * @brief Configures how request retries are handled
 *
 * Similar to Python's requests.adapters.Retry, this class allows configuring:
 * - Number of retry attempts
 * - Backoff factor for exponential backoff
 * - Status codes that should trigger a retry
 * - Whether to retry on connection errors
 * - Whether to add jitter to backoff times
 */
class RetryStrategy {
public:
	/**
	 * @brief Constructs a RetryStrategy with default settings
	 *
	 * @param total Maximum number of retry attempts (default: 3)
	 * @param backoff_factor Factor to apply to backoff timing (default: 0.5)
	 * @param status_forcelist HTTP status codes that should trigger a retry
	 * @param retry_on_connection_error Whether to retry on connection errors (default: true)
	 * @param add_jitter Whether to add random jitter to backoff times (default: true)
	 */
	RetryStrategy(
		int total = 3,
		double backoff_factor = 0.5,
		const std::set<int>& status_forcelist = { 429, 500, 502, 503, 504 },
		bool retry_on_connection_error = true,
		bool add_jitter = true
	);

	/**
	 * @brief Get the sleep time for a given retry attempt
	 *
	 * @param retry_number Current retry attempt (0-based)
	 * @return std::chrono::milliseconds How long to wait before the next attempt
	 */
	std::chrono::milliseconds get_backoff_time(int retry_number) const;

	/**
	 * @brief Check if a request should be retried based on its status code
	 *
	 * @param status_code The HTTP status code to check
	 * @return true if the request should be retried
	 */
	bool should_retry(int status_code) const;

	/**
	 * @brief Check if connection errors should trigger a retry
	 *
	 * @return true if connection errors should trigger a retry
	 */
	bool retry_on_connection_error() const;

	/**
	 * @brief Get the maximum number of retry attempts
	 *
	 * @return int Maximum number of retry attempts
	 */
	int get_total() const;

private:
	int m_total;
	double m_backoff_factor;
	std::set<int> m_status_forcelist;
	bool m_retry_on_connection_error;
	bool m_add_jitter;
};
#endif 