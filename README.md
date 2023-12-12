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



| Trust Solution  | Cipher & Hash        | Min Time   | Max Time   | Mean Time          | Size (Byte) | Latency * | Number of Routines |
|-----------------|----------------------|------------|------------|--------------------|-------------|-----------|--------------------|
| Schnorr Prep    | SECP256K1, SHA-384   | 900        | 6700       | 1650               | N/A         | N/A       | 100                |
| Schnorr Sign    | SECP256K1, SHA-384   | 177666200  | 182516000  | 179071240          | N/A         | N/A       | 100                |
| Schnorr Verify  | SECP256K1, SHA-384   | 88983500   | 97274400   | 91555930           | N/A         | N/A       | 100                |
| Schnorr Total   | SECP256K1, SHA-384   | 266650600  | 279797100  | 270628820          | 422         | N/A       | 100                |
| -----           | -----                | -----      | -----      | -----              | -----       | -----     | -----              |
| PKI Prep        | ECDSA P-384, SHA-384 | 85117400   | 325353100  | 182490240          | N/A         | N/A       | 100                |
| PKI Sign        | ECDSA P-384, SHA-384 | 99297800   | 369332600  | 207644630          | N/A         | N/A       | 100                |
| PKI Verify      | ECDSA P-384, SHA-384 | 287100     | 434600     | 306930             | N/A         | N/A       | 100                |
| PKI Total       | ECDSA P-384, SHA-384 | 184702300  | 695120300  | 390441800          | 3257        | N/A       | 100                |
| -----           | -----                | -----      | -----      | -----              | -----       | -----     | -----              |
| Kerberos Prep   | AES 256 CBC, SHA-384 | 879800     | 1267400    | 1041981            | N/A         | N/A       | 100                |
| Kerberos Sign   | AES 256 CBC, SHA-384 | 2145400    | 4707100    | 2691980            | N/A         | N/A       | 100                |
| Kerberos Verify | AES 256 CBC, SHA-384 | 2190700    | 5257000    | 3033853            | N/A         | N/A       | 100                |
| Kerberos Total  | AES 256 CBC, SHA-384 | 5215900    | 11231500   | 6767814            | 168         | N/A       | 100                |


