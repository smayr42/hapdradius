STRINGIFY(
    CREATE TABLE IF NOT EXISTS users (
        firstname TEXT NOT NULL,
        lastname TEXT NOT NULL,
        username TEXT PRIMARY KEY NOT NULL,
        password TEXT NOT NULL,
        expiration TEXT DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS accounting (
        timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        session TEXT NOT NULL,  /* Acct-Session-Id (string) */
        status INTEGER,         /* Acct-Status-Type (int32) */
        username TEXT,          /* User-Name (string) */
        ap_mac TEXT,            /* Called-Station-Id (string) */
        client_mac TEXT,        /* Calling-Station-Id (string) */
        session_time INTEGER,   /* Acct-Session-Time (int32) */
        input_octets INTEGER,   /* Acct-Input-Octets (int32) */
        output_octets INTEGER,  /* Acct-Output-Octets (int32) */
        terminate_cause INTEGER /* Acct-Terminate-Cause (int32) */
    );

    CREATE TABLE IF NOT EXISTS requests (
        timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        session TEXT,          /* Acct-Session-Id (string) */
        status INTEGER,        /* Radius Message Code */
        username TEXT,         /* User-Name (string) */
        ap_mac TEXT,           /* Called-Station-Id (string) */
        client_mac TEXT        /* Calling-Station-Id (string) */
    );
)

