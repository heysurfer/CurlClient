#include <RetryStrategy.h>

RetryStrategy::RetryStrategy(
	int total,
	double backoff_factor,
	const std::set<int>& status_forcelist,
	bool retry_on_connection_error,
	bool add_jitter
) : m_total(total),
m_backoff_factor(backoff_factor),
m_status_forcelist(status_forcelist),
m_retry_on_connection_error(retry_on_connection_error),
m_add_jitter(add_jitter) {
}

std::chrono::milliseconds RetryStrategy::get_backoff_time(int retry_number) const {
	// Calculate backoff: {backoff factor} * (2 ^ (retry_number))
	double backoff = m_backoff_factor * (1 << retry_number) * 1000;

	if (m_add_jitter) {
		// Add jitter between 0 and 0.1*backoff
		static std::random_device rd;
		static std::mt19937 gen(rd());
		std::uniform_real_distribution<> dis(0, 0.1 * backoff);
		backoff += dis(gen);
	}

	return std::chrono::milliseconds(static_cast<int>(backoff));
}

bool RetryStrategy::should_retry(int status_code) const {
	return m_status_forcelist.find(status_code) != m_status_forcelist.end()
		|| (m_retry_on_connection_error && status_code == 0);
}

bool RetryStrategy::retry_on_connection_error() const {
	return m_retry_on_connection_error;
}

int RetryStrategy::get_total() const {
	return m_total;
}