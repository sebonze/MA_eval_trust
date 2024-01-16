# MA_eval_trust
Evaluating Trust Solution in Digital Aeronautical Communications Systems

The repository MA_eval_trust focuses on evaluating trust solutions in digital aeronautical communications systems. It contains various Python scripts that implement cryptographic protocols and trust solutions, such as Kerberos, PKI, and Schnorr signatures.


| Language      | Files |     % | Code |    % | Comment |    % |
|---------------|-------|-------|------|------|---------|------|
| Python        |    35 |  53.8 | 2584 | 69.4 |     396 | 10.6 |
| Markdown      |     1 |   1.5 |   28 | 82.4 |       0 |  0.0 |
| JSON          |     2 |   3.1 |   21 | 55.3 |       0 |  0.0 |
| ASCII armored |     8 |  12.3 |   16 | 20.5 |       0 |  0.0 |
| __unknown__   |    16 |  24.6 |    0 |  0.0 |       0 |  0.0 |
| __binary__    |     3 |   4.6 |    0 |  0.0 |       0 |  0.0 |
| **Sum**       |   **65** | **100.0** | **2649** | **68.4** |   **396** | **10.2** |




| Trust Solution  | Cipher & Hash        | Min Time  | Max Time  | Mean Time   | Size (Byte) | Latency * | Number of Routines |
|-----------------|----------------------|-----------|-----------|-------------|-------------|-----------|--------------------|
| Schnorr Prep    | SECP256K1, SHA-384   | 800       | 6800      | 942         | -           | N/A       | 100                |
| Schnorr Sign    | SECP256K1, SHA-384   | 175428500 | 190312700 | 178156113   | 195         | N/A       | 100                |
| Schnorr Verify  | SECP256K1, SHA-384   | 87034900  | 99952500  | 88279690    | 227         | N/A       | 100                |
| Schnorr Total   | SECP256K1, SHA-384   | 262464200 | 290272000 | 266436745   | 422         | N/A       | 100                |
| -----           | -----                | -----     | -----     | -----       | -----       | -----     | -----              |
| PKI Prep        | SECP256K1, SHA-384   | 2931900   | 27601800  | 3229384     | -           | N/A       | 100                |
| PKI Sign        | SECP256K1, SHA-384   | 1638300   | 2065900   | 1672176     | 497         | N/A       | 100                |
| PKI Verify      | SECP256K1, SHA-384   | 736000    | 890200    | 752647      | 1200        | N/A       | 100                |
| PKI Total       | SECP256K1, SHA-384   | 5306200   | 30557900  | 5654207     | 1697        | N/A       | 100                |
| -----           | -----                | -----     | -----     | -----       | -----       | -----     | -----              |
| Kerberos Prep   | AES 256 CBC, SHA-384 | 879800    | 1224700   | 986164      | --          | N/A       | 100                |
| Kerberos Sign   | AES 256 CBC, SHA-384 | 2145400   | 4707100   | 2423686     | 168         | N/A       | 100                |
| Kerberos Verify | AES 256 CBC, SHA-384 | 2190700   | 2278100   | 2239000     | 56          | N/A       | 100                |
| Kerberos Total  | AES 256 CBC, SHA-384 | 5215900   | 8209900   | 5648851     | 224         | N/A       | 100                |
| -----           | -----                | -----     | -----     | -----       | -----       | -----     | -----              |


* Latency is the time between the first and the last message of a routine.
* The time is measured in nanoseconds.
* The size is measured in bytes.
* The number of routines is the number of times a routine is executed.
* The mean time is the mean of the time of all routines.
* The minimum and maximum time are the minimum and maximum of the time of all routines.
* The total time is the sum of the time of all routines.
