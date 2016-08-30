INSERT INTO users
    (firstname, lastname, username, password, expiration)
VALUES
    ('first1', 'last1', 'user1', 'pass1', date('now')),
    ('first2', 'last2', 'user2', 'pass2', NULL),
    ('first3', 'last3', 'user3', 'pass3', date('now','+9 months'));
