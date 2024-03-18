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


| Trust Solution  | Cipher & Hash          | Min Time | Max Time | Mean Time           | 95th Percentile    | Size (Byte) | Latency | Number of Routines |
|-----------------|------------------------|----------|----------|---------------------|--------------------|-------------|---------|--------------------|
| Schnorr Prep    | SHA-384                | 17890200 | 19411400 | 18436013            | 19250390.0         | 256         | N/A     | 1000               |
| Schnorr Sign    | SHA-384                | 2300     | 21700    | 2674                | 2905.0             | 48          | N/A     | 1000               |
| Schnorr Verify  | SHA-384                | 22023000 | 23771100 | 22326745            | 23422285.0         | 256         | N/A     | 1000               |
| Schnorr Total   | SHA-384                | 39915500 | 43204200 | 40765432            | 22817715.0         | 560         | N/A     | 1000               |
| -----           | -----                  | -----    | -----    | -----               | -----              | -----       | -----   | -----              |
| PKI Prep        | SECP256K1, SHA-384     | 1171800  | 1672800  | 1278124             | 1512965.0          | 605         | N/A     | 1000               |
| PKI Sign        | SECP256K1, SHA-384     | 601100   | 1068000  | 672769              | 832715.0           | 868         | N/A     | 1000               |
| PKI Verify      | SECP256K1, SHA-384     | 4617900  | 5560200  | 4941055             | 5348515.0          | 1511        | N/A     | 1000               |
| PKI Total       | SECP256K1, SHA-384     | 6390800  | 8301000  | 6891948             | 5193145.0          | 2984        | N/A     | 1000               |
| -----           | -----                  | -----    | -----    | -----               | -----              | -----       | -----   | -----              |
| Kerberos Prep   | AES 256 CBC, SHA-384   | 879800   | 1526700  | 1018478.2608695652  | 1238200.0          | 56          | N/A     | 1000               |
| Kerberos Sign   | AES 256 CBC, SHA-384   | 2145400  | 4769600  | 2545370.588235294   | 4723760.0          | 56          | N/A     | 1000               |
| Kerberos Verify | AES 256 CBC, SHA-384   | 2190700  | 5436700  | 2544062.962962963   | 4603590.0          | 56          | N/A     | 1000               |
| Kerberos Total  | AES 256 CBC, SHA-384   | 5215900  | 11733000 | 6107911.812067822   | 4391660.0          | 168         | N/A     | 1000               |
| -----           | -----                  | -----    | -----    | -----               | -----              | -----       | -----   | -----              |

This table provides a comprehensive overview of the performance metrics for each trust solution, including latency, which is crucial for analysis and conclusions.

* Latency is the time between the first and the last message of a routine.
* The time is measured in nanoseconds.
* The size is measured in bytes.
* The number of routines is the number of times a routine is executed.
* The mean time is the mean of the time of all routines.
* The minimum and maximum time are the minimum and maximum of the time of all routines.
* The total time is the sum of the time of all routines.
