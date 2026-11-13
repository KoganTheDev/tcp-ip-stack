window.BENCHMARK_DATA = {
  "lastUpdate": 1794575572199,
  "repoUrl": "https://github.com/KoganTheDev/tcp-ip-stack",
  "entries": {
    "tcp-ip-stack microbenchmarks": [
      {
        "commit": {
          "author": {
            "email": "109174220+KoganTheDev@users.noreply.github.com",
            "name": "Yuval Kogan",
            "username": "KoganTheDev"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ad05df9267d11308f4bb1a7b234228323136e0f7",
          "message": "Merge pull request #14 from KoganTheDev/roadmap\n\nRoadmap: test/CI infrastructure, TCP correctness and loss recovery, ustack socket+epoll API, dual-stack IPv6",
          "timestamp": "2026-11-13T15:11:03+02:00",
          "tree_id": "2a8ea5c52b9e35c43fd6bb1576e1c1602ec80934",
          "url": "https://github.com/KoganTheDev/tcp-ip-stack/commit/ad05df9267d11308f4bb1a7b234228323136e0f7"
        },
        "date": 1794575571822,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BM_InternetChecksum/64",
            "value": 7.722554812627173,
            "unit": "ns/iter",
            "extra": "iterations: 90549482\ncpu: 7.722181304140427 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/576",
            "value": 52.086385095038125,
            "unit": "ns/iter",
            "extra": "iterations: 13453131\ncpu: 52.07196859972598 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/1500",
            "value": 133.93904779567842,
            "unit": "ns/iter",
            "extra": "iterations: 5230180\ncpu: 133.89818839886965 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/9000",
            "value": 798.2730081196975,
            "unit": "ns/iter",
            "extra": "iterations: 877864\ncpu: 797.9852448670862 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseEthernetIpTcp",
            "value": 633.8428767067991,
            "unit": "ns/iter",
            "extra": "iterations: 1113565\ncpu: 633.801031821223 ns\nthreads: 1"
          },
          {
            "name": "BM_SerializeEthernetIpTcp",
            "value": 1552.2891436054113,
            "unit": "ns/iter",
            "extra": "iterations: 445986\ncpu: 1552.230726973493 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/1",
            "value": 375.8559966158665,
            "unit": "ns/iter",
            "extra": "iterations: 1834443\ncpu: 375.85153477104467 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/8",
            "value": 1306.7915717306653,
            "unit": "ns/iter",
            "extra": "iterations: 536765\ncpu: 1306.2436857842827 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/32",
            "value": 4823.071325438365,
            "unit": "ns/iter",
            "extra": "iterations: 144058\ncpu: 4822.965270932546 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/16",
            "value": 6260.272064290909,
            "unit": "ns/iter",
            "extra": "iterations: 111073\ncpu: 6267.490947394239 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/256",
            "value": 126106.77378356026,
            "unit": "ns/iter",
            "extra": "iterations: 5508\ncpu: 126144.6192810325 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/1000",
            "value": 568222.881933569,
            "unit": "ns/iter",
            "extra": "iterations: 1262\ncpu: 567972.3177495553 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/4096",
            "value": 2101201.5014923518,
            "unit": "ns/iter",
            "extra": "iterations: 335\ncpu: 2099799.7910447656 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/16",
            "value": 11155.495510036859,
            "unit": "ns/iter",
            "extra": "iterations: 63030\ncpu: 11172.408297636284 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/256",
            "value": 198880.85059432327,
            "unit": "ns/iter",
            "extra": "iterations: 3534\ncpu: 198904.6140350908 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/1000",
            "value": 896148.3299232676,
            "unit": "ns/iter",
            "extra": "iterations: 782\ncpu: 896096.505115041 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/4096",
            "value": 2085085.5505954209,
            "unit": "ns/iter",
            "extra": "iterations: 336\ncpu: 2084710.9672619058 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/16",
            "value": 221.16423387767279,
            "unit": "ns/iter",
            "extra": "iterations: 3176464\ncpu: 221.10439438318883 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/64",
            "value": 352.0474947276806,
            "unit": "ns/iter",
            "extra": "iterations: 1994853\ncpu: 352.01616209314625 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/256",
            "value": 832.5045405071512,
            "unit": "ns/iter",
            "extra": "iterations: 802994\ncpu: 832.4821194180757 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/512",
            "value": 1570.9564961855713,
            "unit": "ns/iter",
            "extra": "iterations: 428767\ncpu: 1570.8706686848539 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1",
            "value": 18.802122931572182,
            "unit": "ns/iter",
            "extra": "iterations: 37521134\ncpu: 18.801538914042474 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10",
            "value": 18.690295273528076,
            "unit": "ns/iter",
            "extra": "iterations: 37394954\ncpu: 18.688538031093668 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/100",
            "value": 18.73123476632724,
            "unit": "ns/iter",
            "extra": "iterations: 37487676\ncpu: 18.72980685705889 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1000",
            "value": 18.706281184786985,
            "unit": "ns/iter",
            "extra": "iterations: 37520899\ncpu: 18.705010799448047 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10000",
            "value": 18.653097508765182,
            "unit": "ns/iter",
            "extra": "iterations: 37262445\ncpu: 18.651363859778964 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections_BigO",
            "unit": "ns/iter",
            "extra": "iterations: undefined\ncpu: undefined ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections_RMS",
            "unit": "undefined/iter",
            "extra": "iterations: undefined\ncpu: undefined undefined\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/0/real_time",
            "value": 12.859888799999908,
            "unit": "ms/iter",
            "extra": "iterations: 55\ncpu: 12.859481945454574 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/10/real_time",
            "value": 14.502074458333366,
            "unit": "ms/iter",
            "extra": "iterations: 48\ncpu: 14.501191666666635 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/50/real_time",
            "value": 17.536954750000078,
            "unit": "ms/iter",
            "extra": "iterations: 40\ncpu: 17.536273275000003 ms\nthreads: 1"
          }
        ]
      }
    ]
  }
}