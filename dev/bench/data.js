window.BENCHMARK_DATA = {
  "lastUpdate": 1795127067492,
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
          "id": "83697b6e94840634215813d8756f2549e339447f",
          "message": "Merge pull request #16 from KoganTheDev/feat/minshall-nagle\n\ntcp: Minshall's Nagle (fix ~41 ms per echo round)",
          "timestamp": "2026-11-15T21:28:19+02:00",
          "tree_id": "9fdae997b323e32fb473b4c05e1eeb6192610d95",
          "url": "https://github.com/KoganTheDev/tcp-ip-stack/commit/83697b6e94840634215813d8756f2549e339447f"
        },
        "date": 1794770965157,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BM_InternetChecksum/64",
            "value": 3.0883159667743865,
            "unit": "ns/iter",
            "extra": "iterations: 224773659\ncpu: 3.087750931705035 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/576",
            "value": 20.282700793203794,
            "unit": "ns/iter",
            "extra": "iterations: 34765594\ncpu: 20.27820634964558 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/1500",
            "value": 50.210698299999734,
            "unit": "ns/iter",
            "extra": "iterations: 10000000\ncpu: 50.206522700000015 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/9000",
            "value": 302.1037110559674,
            "unit": "ns/iter",
            "extra": "iterations: 2266875\ncpu: 302.07792401433693 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseEthernetIpTcp",
            "value": 301.72794171039624,
            "unit": "ns/iter",
            "extra": "iterations: 2299827\ncpu: 301.7073632060151 ns\nthreads: 1"
          },
          {
            "name": "BM_SerializeEthernetIpTcp",
            "value": 789.8356904286445,
            "unit": "ns/iter",
            "extra": "iterations: 882937\ncpu: 789.6332864066184 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/1",
            "value": 181.6543829825235,
            "unit": "ns/iter",
            "extra": "iterations: 4010089\ncpu: 181.55976463365272 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/8",
            "value": 627.2809246754094,
            "unit": "ns/iter",
            "extra": "iterations: 1136269\ncpu: 627.1681239213601 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/32",
            "value": 2482.709328172636,
            "unit": "ns/iter",
            "extra": "iterations: 295567\ncpu: 2481.6596473895925 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/16",
            "value": 3621.016089953795,
            "unit": "ns/iter",
            "extra": "iterations: 187011\ncpu: 3634.833213020276 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/256",
            "value": 68166.35222347568,
            "unit": "ns/iter",
            "extra": "iterations: 9917\ncpu: 68153.4336997047 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/1000",
            "value": 285748.0486999813,
            "unit": "ns/iter",
            "extra": "iterations: 2423\ncpu: 285700.96079239616 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/4096",
            "value": 1238116.6196428214,
            "unit": "ns/iter",
            "extra": "iterations: 560\ncpu: 1237899.7642856676 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/16",
            "value": 5827.444213292756,
            "unit": "ns/iter",
            "extra": "iterations: 116802\ncpu: 5839.941028409972 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/256",
            "value": 95413.07650349084,
            "unit": "ns/iter",
            "extra": "iterations: 7333\ncpu: 95414.12341469436 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/1000",
            "value": 453766.20405507594,
            "unit": "ns/iter",
            "extra": "iterations: 1529\ncpu: 453675.85676913883 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/4096",
            "value": 1152710.8764228062,
            "unit": "ns/iter",
            "extra": "iterations: 615\ncpu: 1152447.4227642007 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/16",
            "value": 100.31647876788644,
            "unit": "ns/iter",
            "extra": "iterations: 7252575\ncpu: 100.31138278473526 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/64",
            "value": 194.32270963909707,
            "unit": "ns/iter",
            "extra": "iterations: 3609322\ncpu: 194.30736880777047 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/256",
            "value": 584.5894824172236,
            "unit": "ns/iter",
            "extra": "iterations: 1234276\ncpu: 584.4801883857436 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/512",
            "value": 975.9304248825011,
            "unit": "ns/iter",
            "extra": "iterations: 699158\ncpu: 975.7455367742313 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1",
            "value": 10.958297686990113,
            "unit": "ns/iter",
            "extra": "iterations: 64792761\ncpu: 10.956437988496875 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10",
            "value": 10.836381140410962,
            "unit": "ns/iter",
            "extra": "iterations: 64659331\ncpu: 10.834167863567863 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/100",
            "value": 10.795019059508624,
            "unit": "ns/iter",
            "extra": "iterations: 65022138\ncpu: 10.793980997671902 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1000",
            "value": 10.825975522062784,
            "unit": "ns/iter",
            "extra": "iterations: 64972877\ncpu: 10.825464154834956 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10000",
            "value": 11.09830132765441,
            "unit": "ns/iter",
            "extra": "iterations: 63291841\ncpu: 11.097456669019982 ns\nthreads: 1"
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
            "value": 7.13298277319582,
            "unit": "ms/iter",
            "extra": "iterations: 97\ncpu: 7.1319162783505226 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/10/real_time",
            "value": 7.555312719101229,
            "unit": "ms/iter",
            "extra": "iterations: 89\ncpu: 7.554834494382039 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/50/real_time",
            "value": 9.055734784810292,
            "unit": "ms/iter",
            "extra": "iterations: 79\ncpu: 9.055128607594911 ms\nthreads: 1"
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
          "id": "872a757cb8f7dba6e242ef4aa82ff773d1a1e139",
          "message": "Merge pull request #17 from KoganTheDev/feat/burst-latency\n\nBurst latency: no frame drops, half-open cap follows the backlog, optimised server",
          "timestamp": "2026-11-19T11:58:34+02:00",
          "tree_id": "ac8328b4b5001f0150a24121d5552b783a3f5ea1",
          "url": "https://github.com/KoganTheDev/tcp-ip-stack/commit/872a757cb8f7dba6e242ef4aa82ff773d1a1e139"
        },
        "date": 1795082397819,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BM_EchoBurst/200/iterations:3/manual_time",
            "value": 35.79267433333333,
            "unit": "ms/iter",
            "extra": "iterations: 3\ncpu: 36.71936733333333 ms\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/64",
            "value": 7.728156059405114,
            "unit": "ns/iter",
            "extra": "iterations: 90786813\ncpu: 7.724290431915481 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/576",
            "value": 52.33672268221969,
            "unit": "ns/iter",
            "extra": "iterations: 13441028\ncpu: 52.333630656821775 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/1500",
            "value": 134.05097609051893,
            "unit": "ns/iter",
            "extra": "iterations: 5140763\ncpu: 134.00946240859577 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/9000",
            "value": 800.7557853820308,
            "unit": "ns/iter",
            "extra": "iterations: 829418\ncpu: 800.7536802914818 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseEthernetIpTcp",
            "value": 748.4243920357903,
            "unit": "ns/iter",
            "extra": "iterations: 933731\ncpu: 748.1609264338449 ns\nthreads: 1"
          },
          {
            "name": "BM_SerializeEthernetIpTcp",
            "value": 1825.7989540508686,
            "unit": "ns/iter",
            "extra": "iterations: 382619\ncpu: 1825.3913187792562 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/1",
            "value": 365.0631510242983,
            "unit": "ns/iter",
            "extra": "iterations: 1912083\ncpu: 364.9681499181785 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/8",
            "value": 1255.8554533249967,
            "unit": "ns/iter",
            "extra": "iterations: 557889\ncpu: 1255.528329112063 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/32",
            "value": 4918.928375937741,
            "unit": "ns/iter",
            "extra": "iterations: 143960\ncpu: 4916.827236732423 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/16",
            "value": 6654.894286939522,
            "unit": "ns/iter",
            "extra": "iterations: 104358\ncpu: 6665.254383948312 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/256",
            "value": 132073.96750950135,
            "unit": "ns/iter",
            "extra": "iterations: 5263\ncpu: 132085.68326047776 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/1000",
            "value": 556711.8926014932,
            "unit": "ns/iter",
            "extra": "iterations: 1257\ncpu: 556698.1201272914 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/4096",
            "value": 2156583.7760725124,
            "unit": "ns/iter",
            "extra": "iterations: 326\ncpu: 2155717.5736197345 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/16",
            "value": 12000.165857138856,
            "unit": "ns/iter",
            "extra": "iterations: 59919\ncpu: 12003.014686493929 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/256",
            "value": 213530.23823921528,
            "unit": "ns/iter",
            "extra": "iterations: 3295\ncpu: 213475.16631258704 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/1000",
            "value": 944405.8040541733,
            "unit": "ns/iter",
            "extra": "iterations: 740\ncpu: 944572.7716216738 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/4096",
            "value": 2203876.9371047253,
            "unit": "ns/iter",
            "extra": "iterations: 318\ncpu: 2204131.682389958 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/16",
            "value": 201.9306917003131,
            "unit": "ns/iter",
            "extra": "iterations: 3478732\ncpu: 201.92120261060646 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/64",
            "value": 331.67281757633265,
            "unit": "ns/iter",
            "extra": "iterations: 2117302\ncpu: 331.6766960972037 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/256",
            "value": 849.0199098719341,
            "unit": "ns/iter",
            "extra": "iterations: 771125\ncpu: 848.9510675960462 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/512",
            "value": 1643.5829617154443,
            "unit": "ns/iter",
            "extra": "iterations: 421580\ncpu: 1643.0510176004586 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1",
            "value": 18.62539829488127,
            "unit": "ns/iter",
            "extra": "iterations: 37564191\ncpu: 18.620830540447447 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10",
            "value": 18.659218464994407,
            "unit": "ns/iter",
            "extra": "iterations: 37677954\ncpu: 18.654915763207327 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/100",
            "value": 18.65119054875722,
            "unit": "ns/iter",
            "extra": "iterations: 37469948\ncpu: 18.647227265967857 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1000",
            "value": 18.686019185063323,
            "unit": "ns/iter",
            "extra": "iterations: 37228023\ncpu: 18.684411337126335 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10000",
            "value": 18.63406979661858,
            "unit": "ns/iter",
            "extra": "iterations: 37513479\ncpu: 18.634469946122515 ns\nthreads: 1"
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
            "value": 12.993366351852105,
            "unit": "ms/iter",
            "extra": "iterations: 54\ncpu: 12.992626740740787 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/10/real_time",
            "value": 14.858536170212565,
            "unit": "ms/iter",
            "extra": "iterations: 47\ncpu: 14.857558042553165 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/50/real_time",
            "value": 17.65854135000069,
            "unit": "ms/iter",
            "extra": "iterations: 40\ncpu: 17.65644824999999 ms\nthreads: 1"
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
          "id": "8ac58487b13a90e4d0df5547a4691bd2a376ce45",
          "message": "Merge pull request #20 from KoganTheDev/feat/recovery\n\nTCP recovery: D-SACK, RACK reordering window, congestion undo, Eifel and F-RTO",
          "timestamp": "2026-11-20T00:16:22+02:00",
          "tree_id": "a9790410e723b5420ff86c460b0a4de364557824",
          "url": "https://github.com/KoganTheDev/tcp-ip-stack/commit/8ac58487b13a90e4d0df5547a4691bd2a376ce45"
        },
        "date": 1795126680413,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BM_EchoBurst/200/iterations:3/manual_time",
            "value": 29.48776833333333,
            "unit": "ms/iter",
            "extra": "iterations: 3\ncpu: 30.386534333333334 ms\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/64",
            "value": 7.665463356300902,
            "unit": "ns/iter",
            "extra": "iterations: 90514470\ncpu: 7.665272624366028 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/576",
            "value": 42.04078434919569,
            "unit": "ns/iter",
            "extra": "iterations: 16672523\ncpu: 42.03308959297883 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/1500",
            "value": 113.3701808254392,
            "unit": "ns/iter",
            "extra": "iterations: 6171311\ncpu: 113.35759468288019 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/9000",
            "value": 663.9182897571258,
            "unit": "ns/iter",
            "extra": "iterations: 1060785\ncpu: 663.8284873937697 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseEthernetIpTcp",
            "value": 703.4130340940769,
            "unit": "ns/iter",
            "extra": "iterations: 986858\ncpu: 703.3614451116568 ns\nthreads: 1"
          },
          {
            "name": "BM_SerializeEthernetIpTcp",
            "value": 1734.4525455285532,
            "unit": "ns/iter",
            "extra": "iterations: 405515\ncpu: 1734.3620014056203 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/1",
            "value": 341.25089185622,
            "unit": "ns/iter",
            "extra": "iterations: 2055264\ncpu: 341.2299665639059 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/8",
            "value": 1200.4517842258376,
            "unit": "ns/iter",
            "extra": "iterations: 584259\ncpu: 1200.3513767010866 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/32",
            "value": 4781.224903638855,
            "unit": "ns/iter",
            "extra": "iterations: 147103\ncpu: 4779.692147678838 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/16",
            "value": 5892.287548416806,
            "unit": "ns/iter",
            "extra": "iterations: 119013\ncpu: 5890.303059331127 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/256",
            "value": 141455.67351431018,
            "unit": "ns/iter",
            "extra": "iterations: 4965\ncpu: 141493.92185297908 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/1000",
            "value": 612007.3940722701,
            "unit": "ns/iter",
            "extra": "iterations: 1147\ncpu: 611932.8622493295 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/4096",
            "value": 2329886.4668881968,
            "unit": "ns/iter",
            "extra": "iterations: 302\ncpu: 2329597.5695364163 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/16",
            "value": 10361.129530961543,
            "unit": "ns/iter",
            "extra": "iterations: 68887\ncpu: 10358.981128510854 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/256",
            "value": 220405.93131700813,
            "unit": "ns/iter",
            "extra": "iterations: 3174\ncpu: 220436.2696912378 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/1000",
            "value": 1006148.7482012257,
            "unit": "ns/iter",
            "extra": "iterations: 695\ncpu: 1006096.3928056883 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/4096",
            "value": 2201186.038094362,
            "unit": "ns/iter",
            "extra": "iterations: 315\ncpu: 2201020.469841261 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/16",
            "value": 224.411864157816,
            "unit": "ns/iter",
            "extra": "iterations: 3097565\ncpu: 224.394597692058 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/64",
            "value": 372.1777700988937,
            "unit": "ns/iter",
            "extra": "iterations: 1872379\ncpu: 372.15039156068315 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/256",
            "value": 828.0015835067128,
            "unit": "ns/iter",
            "extra": "iterations: 870852\ncpu: 827.97194930941 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/512",
            "value": 1681.8290960988495,
            "unit": "ns/iter",
            "extra": "iterations: 421108\ncpu: 1681.7274000968875 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1",
            "value": 13.905933201330688,
            "unit": "ns/iter",
            "extra": "iterations: 50797838\ncpu: 13.904835142787046 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10",
            "value": 16.474992028893215,
            "unit": "ns/iter",
            "extra": "iterations: 50460371\ncpu: 16.473865045502734 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/100",
            "value": 13.913694066379817,
            "unit": "ns/iter",
            "extra": "iterations: 42934464\ncpu: 13.913096038650941 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1000",
            "value": 16.380082329439244,
            "unit": "ns/iter",
            "extra": "iterations: 50382950\ncpu: 16.37852100760276 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10000",
            "value": 13.906449197108278,
            "unit": "ns/iter",
            "extra": "iterations: 42880423\ncpu: 13.904875192112716 ns\nthreads: 1"
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
            "value": 13.593995039215377,
            "unit": "ms/iter",
            "extra": "iterations: 51\ncpu: 13.592368117647002 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/10/real_time",
            "value": 13.712014647058693,
            "unit": "ms/iter",
            "extra": "iterations: 51\ncpu: 13.710610058823518 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/50/real_time",
            "value": 17.422446200000508,
            "unit": "ms/iter",
            "extra": "iterations: 40\ncpu: 17.420640100000018 ms\nthreads: 1"
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
          "id": "ee7e938d7cc15db99e3f2ecebad10c18b7fc9e5c",
          "message": "Merge pull request #22 from KoganTheDev/feat/loopback\n\nLoopback: 127/8, ::1 and own addresses stay inside the stack",
          "timestamp": "2026-11-20T00:23:10+02:00",
          "tree_id": "0e605ce0d29bfde7a4877387833ed93a00f3df61",
          "url": "https://github.com/KoganTheDev/tcp-ip-stack/commit/ee7e938d7cc15db99e3f2ecebad10c18b7fc9e5c"
        },
        "date": 1795127067134,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BM_EchoBurst/200/iterations:3/manual_time",
            "value": 38.77819866666667,
            "unit": "ms/iter",
            "extra": "iterations: 3\ncpu: 39.66649133333333 ms\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/64",
            "value": 7.6009868332729,
            "unit": "ns/iter",
            "extra": "iterations: 91773152\ncpu: 7.59913875465452 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/576",
            "value": 52.121052468932184,
            "unit": "ns/iter",
            "extra": "iterations: 13461642\ncpu: 52.111620632906444 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/1500",
            "value": 133.93288708589418,
            "unit": "ns/iter",
            "extra": "iterations: 5233270\ncpu: 133.89823781306904 ns\nthreads: 1"
          },
          {
            "name": "BM_InternetChecksum/9000",
            "value": 801.7047612400577,
            "unit": "ns/iter",
            "extra": "iterations: 873974\ncpu: 801.6912505406343 ns\nthreads: 1"
          },
          {
            "name": "BM_ParseEthernetIpTcp",
            "value": 713.1963810936475,
            "unit": "ns/iter",
            "extra": "iterations: 986928\ncpu: 713.0071383120145 ns\nthreads: 1"
          },
          {
            "name": "BM_SerializeEthernetIpTcp",
            "value": 1783.030042338337,
            "unit": "ns/iter",
            "extra": "iterations: 392080\ncpu: 1782.6301418077956 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/1",
            "value": 373.4455048226095,
            "unit": "ns/iter",
            "extra": "iterations: 1924785\ncpu: 373.37137706289275 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/8",
            "value": 1292.3942315494626,
            "unit": "ns/iter",
            "extra": "iterations: 542260\ncpu: 1292.1281488584807 ns\nthreads: 1"
          },
          {
            "name": "BM_DnsParseResponse/32",
            "value": 4798.003134796016,
            "unit": "ns/iter",
            "extra": "iterations: 144826\ncpu: 4797.807175507154 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/16",
            "value": 6987.498869026835,
            "unit": "ns/iter",
            "extra": "iterations: 101239\ncpu: 6994.345696816414 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/256",
            "value": 136274.49640582193,
            "unit": "ns/iter",
            "extra": "iterations: 5147\ncpu: 136284.4861084157 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/1000",
            "value": 588538.8301265354,
            "unit": "ns/iter",
            "extra": "iterations: 1195\ncpu: 588588.3029289012 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/0/4096",
            "value": 2308974.138612025,
            "unit": "ns/iter",
            "extra": "iterations: 303\ncpu: 2307782.0891088755 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/16",
            "value": 11803.712336504157,
            "unit": "ns/iter",
            "extra": "iterations: 60390\ncpu: 11818.28362311738 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/256",
            "value": 214185.4291275799,
            "unit": "ns/iter",
            "extra": "iterations: 3337\ncpu: 214200.2256518002 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/1000",
            "value": 989487.5969098585,
            "unit": "ns/iter",
            "extra": "iterations: 712\ncpu: 989482.2766854028 ns\nthreads: 1"
          },
          {
            "name": "BM_ReorderBuffer/1/4096",
            "value": 2279655.0977191087,
            "unit": "ns/iter",
            "extra": "iterations: 307\ncpu: 2279590.3843648387 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/16",
            "value": 238.4151062799974,
            "unit": "ns/iter",
            "extra": "iterations: 2935971\ncpu: 238.34909506939903 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/64",
            "value": 374.1954596159898,
            "unit": "ns/iter",
            "extra": "iterations: 1879841\ncpu: 374.15463541863494 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/256",
            "value": 861.5184248275414,
            "unit": "ns/iter",
            "extra": "iterations: 801690\ncpu: 861.4329603712157 ns\nthreads: 1"
          },
          {
            "name": "BM_SackScoreboardWalk/512",
            "value": 1641.1324129634017,
            "unit": "ns/iter",
            "extra": "iterations: 410632\ncpu: 1641.1223674725827 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1",
            "value": 16.510820658202647,
            "unit": "ns/iter",
            "extra": "iterations: 42439008\ncpu: 16.509908596355526 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10",
            "value": 16.471526506461988,
            "unit": "ns/iter",
            "extra": "iterations: 42336375\ncpu: 16.470693156889272 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/100",
            "value": 16.47808281661043,
            "unit": "ns/iter",
            "extra": "iterations: 42266859\ncpu: 16.477031449154993 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/1000",
            "value": 16.517270095204662,
            "unit": "ns/iter",
            "extra": "iterations: 42187376\ncpu: 16.516025860437477 ns\nthreads: 1"
          },
          {
            "name": "BM_OnTimePassedIdleConnections/10000",
            "value": 16.496350363421417,
            "unit": "ns/iter",
            "extra": "iterations: 42596844\ncpu: 16.495372004555072 ns\nthreads: 1"
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
            "value": 12.683873309091807,
            "unit": "ms/iter",
            "extra": "iterations: 55\ncpu: 12.682424381818176 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/10/real_time",
            "value": 14.174423320000642,
            "unit": "ms/iter",
            "extra": "iterations: 50\ncpu: 14.174467839999991 ms\nthreads: 1"
          },
          {
            "name": "BM_SimulatedBulkTransfer/50/real_time",
            "value": 18.020407102564825,
            "unit": "ms/iter",
            "extra": "iterations: 39\ncpu: 18.01887312820519 ms\nthreads: 1"
          }
        ]
      }
    ]
  }
}