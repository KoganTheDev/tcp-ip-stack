window.BENCHMARK_DATA = {
  "lastUpdate": 1794649775608,
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
      },
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
          "id": "4e12726b8fda7bd0737845e5597c1d41e362f0f5",
          "message": "Merge pull request #15 from KoganTheDev/fix/nightly\n\nNightly fixes: SYN-cookie reset under jitter, loadgen timeout bug, Mull install",
          "timestamp": "2026-11-14T11:48:18+02:00",
          "tree_id": "926a35a1562972b34db54a291fe70c17bd85003d",
          "url": "https://github.com/KoganTheDev/tcp-ip-stack/commit/4e12726b8fda7bd0737845e5597c1d41e362f0f5"
        },
        "date": 1794649775243,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BM_InternetChecksum/64",
            "value": 4.3702592794660085,
            "unit": "ns/iter",
            "extra": "iterations: 158727533\ncpu: 4.3705291822307855 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/576",
            "value": 27.748806762950156,
            "unit": "ns/iter",
            "extra": "iterations: 25804596\ncpu: 27.748965494363862 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/1500",
            "value": 69.29999207648613,
            "unit": "ns/iter",
            "extra": "iterations: 10096530\ncpu: 69.28560059743297 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/9000",
            "value": 396.0363906503418,
            "unit": "ns/iter",
            "extra": "iterations: 1778204\ncpu: 395.9202532442849 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseEthernetIpTcp",
            "value": 508.7064377149944,
            "unit": "ns/iter",
            "extra": "iterations: 1386377\ncpu: 508.45311628799396 ns\nthreads: 1"
          },
          {
            "name": "BM_SerializeEthernetIpTcp",
            "value": 1183.2299115440178,
            "unit": "ns/iter",
            "extra": "iterations: 594533\ncpu: 1183.0623750069387 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/1",
            "value": 286.1889671766394,
            "unit": "ns/iter",
            "extra": "iterations: 2492798\ncpu: 286.099376684352 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/8",
            "value": 1059.2400738507683,
            "unit": "ns/iter",
            "extra": "iterations: 662417\ncpu: 1059.0850038570866 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/32",
            "value": 3942.6365136241698,
            "unit": "ns/iter",
            "extra": "iterations: 176378\ncpu: 3941.9656533127686 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/16",
            "value": 5029.035169998934,
            "unit": "ns/iter",
            "extra": "iterations: 100000\ncpu: 5043.203959998408 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/256",
            "value": 89697.9097329314,
            "unit": "ns/iter",
            "extra": "iterations: 7788\ncpu: 89745.84655880743 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/1000",
            "value": 419742.09795675025,
            "unit": "ns/iter",
            "extra": "iterations: 1664\ncpu: 419766.83954326913 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/4096",
            "value": 1659989.2775121285,
            "unit": "ns/iter",
            "extra": "iterations: 418\ncpu: 1660276.6196172407 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/16",
            "value": 8244.805491645982,
            "unit": "ns/iter",
            "extra": "iterations: 84310\ncpu: 8267.702004505689 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/256",
            "value": 139864.97844145383,
            "unit": "ns/iter",
            "extra": "iterations: 5056\ncpu: 139924.92207277234 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/1000",
            "value": 671463.3486149894,
            "unit": "ns/iter",
            "extra": "iterations: 1047\ncpu: 671625.9140401082 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/4096",
            "value": 1651326.4215461665,
            "unit": "ns/iter",
            "extra": "iterations: 427\ncpu: 1651623.5058548122 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/16",
            "value": 148.45941358142193,
            "unit": "ns/iter",
            "extra": "iterations: 4729932\ncpu: 148.4527523862921 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/64",
            "value": 259.7023605118303,
            "unit": "ns/iter",
            "extra": "iterations: 2688400\ncpu: 259.6899628031544 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/256",
            "value": 655.3199185749361,
            "unit": "ns/iter",
            "extra": "iterations: 1076327\ncpu: 655.2862856734073 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/512",
            "value": 1316.1865161401854,
            "unit": "ns/iter",
            "extra": "iterations: 525799\ncpu: 1316.1593099264164 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1",
            "value": 16.913011455125364,
            "unit": "ns/iter",
            "extra": "iterations: 41592212\ncpu: 16.912463011104055 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10",
            "value": 17.508924814659792,
            "unit": "ns/iter",
            "extra": "iterations: 41239848\ncpu: 17.507928472481233 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/100",
            "value": 16.864633991471276,
            "unit": "ns/iter",
            "extra": "iterations: 41576900\ncpu: 16.863985530426813 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1000",
            "value": 16.849940149292067,
            "unit": "ns/iter",
            "extra": "iterations: 41417221\ncpu: 16.84915178157408 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10000",
            "value": 16.875099695953203,
            "unit": "ns/iter",
            "extra": "iterations: 41527513\ncpu: 16.874369433103276 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections_BigO",
            "value": null,
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
            "value": 10.6165844428572,
            "unit": "ms/iter",
            "extra": "iterations: 70\ncpu: 10.615834485714311 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/10/real_time",
            "value": 11.579348066666503,
            "unit": "ms/iter",
            "extra": "iterations: 60\ncpu: 11.578435399999993 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/50/real_time",
            "value": 14.024093980000032,
            "unit": "ms/iter",
            "extra": "iterations: 50\ncpu: 14.023557180000026 ms\nthreads: 1"
          }
        ]
      }
    ]
  }
}