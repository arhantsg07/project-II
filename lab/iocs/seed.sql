-- Synthetic indicators used by this lab. The TEST-NET IPs are reserved
-- documentation addresses and are not real hosts.
INSERT INTO iocs (ioc_type, value, source, confidence, context) VALUES
    ('ip', '198.51.100.77', 'lab', 'high',
     'Scenario 2 reverse-shell callback address (RFC 5737 TEST-NET-2)'),
    ('domain', 'x7qz9f.bad-c2-example.net', 'lab', 'high',
     'Scenario 2 synthetic DNS beacon domain'),
    ('ip', '198.51.100.23', 'lab', 'low',
     'Scenario 1 synthetic SSH brute-force source (RFC 5737 TEST-NET-2)')
ON CONFLICT (ioc_type, value) DO NOTHING;

INSERT INTO iocs (ioc_type, value, source, confidence, context, expires_at) VALUES
    ('domain', 'example-malware-c2.test', 'example-public-list', 'medium',
     'Placeholder demonstrating a feed-sourced IOC; replace with a vetted feed entry',
     now() + interval '30 days')
ON CONFLICT (ioc_type, value) DO NOTHING;
