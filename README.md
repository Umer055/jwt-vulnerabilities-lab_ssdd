# JWT Vulnerabilities - Lab

This lab was developed to explain vulnerabilities in the JWT signature system.

### Implemented vulnerabilities.
- [x] Weak Secret
- [x] None Attack
- [x] KID Header Injection - SQL Injection and Path Traversal
- [x] JKU Header Injection
- [x] Algorithm Confusion

### Setup

Run the commands below to initialize the lab:

```
git clone https://github.com/hakaioffsec/jwt-vulnerabilities-lab.git
cd jwt-vulnerabilities-lab
docker build . -t jwt-vuln-lab-hakai
docker run -d -p 8000:8000 -it jwt-vuln-lab-hakai
```

Accessing the lab:
![JWT Lab](./preview.png)
