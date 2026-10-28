INSERT INTO scan_policies (name, limits) VALUES
    ('LIGHT',  '{"maxRequests":200,"requestsPerSecond":2,"maxConcurrency":1,"httpTimeoutMs":10000,"maxResponseBytes":1048576,"maxDurationSec":1800}'),
    ('NORMAL', '{"maxRequests":600,"requestsPerSecond":5,"maxConcurrency":2,"httpTimeoutMs":10000,"maxResponseBytes":1048576,"maxDurationSec":1800}');
