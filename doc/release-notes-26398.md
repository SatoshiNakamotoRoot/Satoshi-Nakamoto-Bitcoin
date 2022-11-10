P2P and network changes
---------

- Transactions of non-witness size below 82, aside from 64, are now allowed by mempool
  and relay policy. This is to better reflect the actual afforded protections
  against CVE-2017-12842 and open up additional use-cases of smaller transaction sizes. (#26398)
