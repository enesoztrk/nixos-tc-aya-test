# tc-aya example with nixos 

1. Start dev-shell ```run_dev.sh```
2. Build : ```build.sh```
3. Run : ```run.sh```


            +---------------------+
            |        Machine A     |
            |  (Attack Scripts)   |
            |   iperf3 Client     |
            |        Port: 1050    |
            +----------+----------+
                       |
                       | iperf3 Traffic
                       |
                       v
            +---------------------+
            |        Machine B     |
            |  (Test Scripts)      |
            |   iperf3 Server      |
            |        Port: 1050    |
            |  Firewall Rules      |
            +---------------------+
