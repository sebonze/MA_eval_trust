# MA_eval_trust
Evaluating Trust Solution in Digital Aeronautical Communications Systems

The repository MA_eval_trust focuses on evaluating trust solutions in digital aeronautical communications systems. It contains various Python scripts that implement cryptographic protocols and trust solutions, such as Kerberos, PKI, and Schnorr signatures.


| Language       | Files |     % | Code |    % | Comment |    % |
|----------------|------:|------:|-----:|-----:|--------:|-----:|
| Python         |    34 |  53.1 | 2426 | 69.1 |     377 | 10.7 |
| JSON           |     2 |   3.1 |   21 | 55.3 |       0 |  0.0 |
| Markdown       |     1 |   1.6 |   19 | 86.4 |       0 |  0.0 |
| ASCII armored  |     8 |  12.5 |   16 |  9.4 |       0 |  0.0 |
| \_\_unknown\_\_ |    16 |  25.0 |    0 |  0.0 |       0 |  0.0 |
| \_\_binary\_\_  |     3 |   4.7 |    0 |  0.0 |       0 |  0.0 |
| **Sum**        |    64 | 100.0 | 2482 | 66.4 |     377 | 10.1 |



| Trust Solution  | Cipher & Hash        | Min Time  | Max Time   | Mean Time         | Size (Byte) | Latency | Number of Routines |
|-----------------|----------------------|-----------|------------|-------------------|-------------|---------|--------------------|
| Schnorr Prep    | SECP256K1, SHA-384   | 900       | 3,200      | 1,270             | N/A         | N/A     | 100                |
| Schnorr Sign    | SECP256K1, SHA-384   | 174,929,100| 192,959,000| 177,941,000       | N/A         | N/A     | 100                |
| Schnorr Verify  | SECP256K1, SHA-384   | 87,539,200 | 88,019,200 | 87,763,610        | N/A         | N/A     | 100                |
| Schnorr Total   | SECP256K1, SHA-384   | 262,469,200| 280,981,400| 265,705,880       | N/A         | N/A     | 100                |
| -----           | -----                | -----     | -----      | -----             | -----       | -----   | -----              |
| PKI Prep        | ECDSA P-384, SHA-384 | 53,195,200 | 344,510,500| 157,667,130       | N/A         | N/A     | 100                |
| PKI Sign        | ECDSA P-384, SHA-384 | 92,423,100 | 591,587,000| 246,438,420       | N/A         | N/A     | 100                |
| PKI Verify      | ECDSA P-384, SHA-384 | 286,100    | 442,200    | 319,230           | N/A         | N/A     | 100                |
| PKI Total       | ECDSA P-384, SHA-384 | 145,904,400| 936,539,700| 404,424,780       | N/A         | N/A     | 100                |
| -----           | -----                | -----     | -----      | -----             | -----       | -----   | -----              |
| Kerberos Prep   | AES 256 CBC, SHA-384 | 890,300    | 1,190,400  | 1,011,658.33      | N/A         | N/A     | 100                |
| Kerberos Sign   | AES 256 CBC, SHA-384 | 2,152,500  | 4,707,100  | 3,025,066.67      | N/A         | N/A     | 100                |
| Kerberos Verify | AES 256 CBC, SHA-384 | 2,194,500  | 5,257,000  | 3,738,700         | N/A         | N/A     | 100                |
| Kerberos Total  | AES 256 CBC, SHA-384 | 5,237,300  | 11,154,500 | 7,775,425.0       | N/A         | N/A     | 100                |
