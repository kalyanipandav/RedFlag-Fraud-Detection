-- RedFlag - Fraud Detection Project
-- Student: Kalyani Pandav

USE redflag;

-- PATTERN 1: VELOCITY FRAUD
-- Find users making 30 or more transactions in one day.

SELECT
    user_id,
    DATE(txn_time) AS transaction_date,
    COUNT(*) AS daily_transactions
FROM redflag.transactions
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY daily_transactions DESC;
-- Findings: 50 user-day combinations had at least 30 transactions.
-- User 14556 made 60 transactions on 2024-05-28.
-- User 14569 made 60 transactions on 2024-04-03.
-- These activities need further investigation.


-- PATTERN 2: ROUND-AMOUNT CLUSTERING
-- Find users with at least 15 transactions of the listed round amounts.

SELECT
    user_id,
    COUNT(*) AS round_transactions
FROM redflag.transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_transactions DESC;
-- Findings: 25 users had at least 15 transactions
-- with amounts matching the specified round-number list.
-- Users 14547, 14551 and 14554 each had 24 such transactions.
-- These users require further investigation.

-- PATTERN 3: CARD TESTING
-- Find users making at least 30 transactions below Rs 10 in one day.

SELECT
    user_id,
    DATE(txn_time) AS transaction_date,
    COUNT(*) AS small_transactions
FROM redflag.transactions
WHERE amount < 10
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY small_transactions DESC;
-- Findings: 20 user-day combinations flagged.
-- User 14569 had 60 transactions below Rs 10 on 2024-04-03.
-- User 14556 had 60 transactions below Rs 10 on 2024-05-28.

-- PATTERN 4: FAILED-THEN-SUCCEEDED (SIMPLIFIED)
-- Find users with at least 20 failed transactions.
-- This version detects repeated failures, not the later success pairs.

SELECT
    user_id,
    COUNT(*) AS failed_transactions
FROM redflag.transactions
WHERE status = 'FAILED'
GROUP BY user_id
HAVING COUNT(*) >= 20
ORDER BY failed_transactions DESC;

-- Findings: 25 users had at least 20 failed transactions.
-- User 14595 had 35 failed transactions.
-- User 14593 had 34 failed transactions.
-- User 14576 had 33 failed transactions.

-- PATTERN 5: ODD-HOUR CONCENTRATION
-- Flag users with at least 30 transactions and 80% or more
-- occurring from 02:00 up to, but not including, 05:00.

SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4
             THEN 1 ELSE 0 END) AS odd_hour_transactions,
    ROUND(
        100.0 * SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4
                         THEN 1 ELSE 0 END) / COUNT(*),
        2
    ) AS odd_hour_percentage
FROM redflag.transactions
GROUP BY user_id
HAVING COUNT(*) >= 30
   AND SUM(CASE WHEN HOUR(txn_time) BETWEEN 2 AND 4
                THEN 1 ELSE 0 END) >= 0.80 * COUNT(*)
ORDER BY odd_hour_percentage DESC, total_transactions DESC;
-- Findings: 20 users matched the odd-hour criteria.
-- User 14606: 49 of 52 transactions during odd hours (94.23%).
-- User 14609: 45 of 48 transactions during odd hours (93.75%).

-- PATTERN 6: MULE ACCOUNTS
-- Detect repeated credits followed within 30 minutes
-- by a debit worth at least 70% of the credit amount.

SELECT
    c.user_id,
    COUNT(*) AS suspicious_credits
FROM redflag.transactions AS c
WHERE c.txn_type = 'CREDIT'
  AND EXISTS (
      SELECT 1
      FROM redflag.transactions AS d
      WHERE d.user_id = c.user_id
        AND d.txn_type = 'DEBIT'
        AND d.txn_time > c.txn_time
        AND d.txn_time <= c.txn_time + INTERVAL 30 MINUTE
        AND d.amount >= 0.70 * c.amount
  )
GROUP BY c.user_id
HAVING COUNT(*) >= 5
ORDER BY suspicious_credits DESC;
-- Findings: 30 users had at least 5 suspicious credits.
-- Users 14637 and 14640 each had 15 qualifying credits.

-- PATTERN 7: REFUND ABUSE
-- Find users with at least 20 transactions and a refund rate above 40%.

SELECT
    user_id,
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN txn_type = 'REFUND'
             THEN 1 ELSE 0 END) AS refund_count,
    ROUND(
        100.0 * SUM(CASE WHEN txn_type = 'REFUND'
                         THEN 1 ELSE 0 END) / COUNT(*),
        2
    ) AS refund_percentage
FROM redflag.transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
   AND SUM(CASE WHEN txn_type = 'REFUND'
                THEN 1 ELSE 0 END) > 0.40 * COUNT(*)
ORDER BY refund_percentage DESC, total_transactions DESC;
-- Findings: 24 users had at least 20 transactions and over 40% refunds.
-- User 14662 had 25 refunds out of 39 transactions (64.10%).
-- User 14670 had 32 refunds out of 50 transactions (64.00%).

-- PATTERN 8: MERCHANT COLLUSION
-- Find merchants whose top 5 users contribute over 60% of total value.

WITH user_volume AS (
    SELECT
        merchant_id,
        user_id,
        SUM(amount) AS user_value
    FROM redflag.transactions
    GROUP BY merchant_id, user_id
),
ranked_users AS (
    SELECT
        merchant_id,
        user_id,
        user_value,
        ROW_NUMBER() OVER (
            PARTITION BY merchant_id
            ORDER BY user_value DESC, user_id
        ) AS user_rank
    FROM user_volume
),
merchant_summary AS (
    SELECT
        merchant_id,
        SUM(user_value) AS total_value,
        SUM(CASE WHEN user_rank <= 5
                 THEN user_value ELSE 0 END) AS top5_value
    FROM ranked_users
    GROUP BY merchant_id
)
SELECT
    merchant_id,
    total_value,
    top5_value,
    ROUND(100.0 * top5_value / total_value, 2) AS top5_percentage
FROM merchant_summary
WHERE top5_value > 0.60 * total_value
ORDER BY top5_percentage DESC, merchant_id;
-- Findings: 15 merchants matched the criteria.
-- Merchant 12: top five users contributed 99.91% of value.
-- Merchant 8: top five users contributed 99.87% of value.

-- PATTERN 9: JUST-UNDER-THRESHOLD
-- Find users with 10 or more transactions of exactly Rs 9999.

SELECT
    user_id,
    COUNT(*) AS threshold_transactions,
    SUM(amount) AS total_amount
FROM redflag.transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY threshold_transactions DESC, user_id;
-- Findings: 20 users made at least 10 transactions of exactly Rs 9999.
-- Users 14680 and 14690 each made 25 such transactions,
-- totalling Rs 249975 per user.

-- PATTERN 10: DORMANT-THEN-ACTIVE
-- Find users with a 90-day inactivity gap followed by at least 15 transactions.

WITH transaction_history AS (
    SELECT
        user_id,
        txn_id,
        txn_time,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time, txn_id
        ) AS previous_time
    FROM redflag.transactions
),
dormant_returns AS (
    SELECT
        user_id,
        txn_time AS return_time,
        previous_time,
        TIMESTAMPDIFF(DAY, previous_time, txn_time) AS gap_days
    FROM transaction_history
    WHERE txn_time >= previous_time + INTERVAL 90 DAY
)
SELECT
    r.user_id,
    r.previous_time,
    r.return_time,
    r.gap_days,
    COUNT(*) AS post_gap_transactions
FROM dormant_returns AS r
JOIN redflag.transactions AS t
    ON t.user_id = r.user_id
   AND t.txn_time >= r.return_time
GROUP BY
    r.user_id, r.previous_time, r.return_time, r.gap_days
HAVING COUNT(*) >= 15
ORDER BY post_gap_transactions DESC, r.user_id;

-- Findings: 26 dormant-return cases matched the criteria.
-- User 14526 had a 102-day gap followed by 55 transactions.
-- User 14701 had a 135-day gap followed by 28 transactions.

-- PATTERN 11: VELOCITY SPIKE
-- Compare the busiest month with the average across Jan-Jun,
-- including months with zero transactions.

WITH monthly_counts AS (
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS txn_month,
        COUNT(*) AS monthly_transactions
    FROM redflag.transactions
    GROUP BY user_id, DATE_FORMAT(txn_time, '%Y-%m')
),
user_summary AS (
    SELECT
        user_id,
        MAX(monthly_transactions) AS peak_transactions,
        SUM(monthly_transactions) / 6.0 AS average_transactions
    FROM monthly_counts
    GROUP BY user_id
)
SELECT
    user_id,
    peak_transactions,
    ROUND(average_transactions, 2) AS average_monthly_transactions,
    ROUND(peak_transactions / average_transactions, 2) AS spike_ratio
FROM user_summary
WHERE peak_transactions >= 20
  AND peak_transactions >= 5 * average_transactions
ORDER BY spike_ratio DESC, user_id;
-- Findings: 66 users matched using the six-month average,
-- including months with zero transactions.
-- User 14522: peak 39, monthly average 6.50, ratio 6.00.
-- Validation note: The six-month average includes the peak month
-- and months with zero transactions. This returns 66 users,
-- compared with the brief's expected 35-45.
-- Example: user 14723 has a peak of 41 and total of 55;
-- 41 / (55 / 6) = 4.47, below the required 5x threshold.
-- The stated rule and expected seeded results are inconsistent.
-- Instructor clarification is needed on the intended baseline.



-- PATTERN 12: GEOGRAPHIC ANOMALY
-- Flag consecutive transactions in different cities
-- occurring within 60 minutes.

WITH transaction_history AS (
    SELECT
        txn_id,
        user_id,
        city,
        txn_time,
        LAG(city) OVER (
            PARTITION BY user_id
            ORDER BY txn_time, txn_id
        ) AS previous_city,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time, txn_id
        ) AS previous_time
    FROM redflag.transactions
)
SELECT
    user_id,
    COUNT(*) AS suspicious_pairs,
    MIN(txn_time) AS first_suspicious_time
FROM transaction_history
WHERE city <> previous_city
  AND txn_time <= previous_time + INTERVAL 60 MINUTE
GROUP BY user_id
ORDER BY suspicious_pairs DESC, user_id;

-- Findings: 15 users had consecutive transactions
-- in different cities within 60 minutes.
-- User 14755 had 8 suspicious pairs.
-- Users 14743 and 14746 had 7 suspicious pairs each.
