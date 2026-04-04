import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of, combineLatest, catchError } from 'rxjs';
import { map } from 'rxjs/operators';
import { NvdCveItem, KevEntry } from '../models/cve';
import { AttackCveService } from './attack-cve.service';

// CWE → ATT&CK technique attackId mapping (common CWEs)
export const CWE_TO_ATTACK: Record<string, string[]> = {
  'CWE-20':  ['T1190', 'T1203'],
  'CWE-22':  ['T1083', 'T1005'],
  'CWE-59':  ['T1574'],
  'CWE-73':  ['T1574'],
  'CWE-77':  ['T1059'],
  'CWE-78':  ['T1059'],
  'CWE-79':  ['T1059.007', 'T1185'],
  'CWE-88':  ['T1059'],
  'CWE-89':  ['T1190'],
  'CWE-90':  ['T1190'],
  'CWE-94':  ['T1059', 'T1203'],
  'CWE-95':  ['T1059'],
  'CWE-96':  ['T1059'],
  'CWE-98':  ['T1190'],
  'CWE-113': ['T1557'],
  'CWE-119': ['T1190', 'T1203'],
  'CWE-120': ['T1190', 'T1203'],
  'CWE-121': ['T1190'],
  'CWE-122': ['T1203'],
  'CWE-123': ['T1203'],
  'CWE-124': ['T1203'],
  'CWE-125': ['T1190', 'T1005'],
  'CWE-126': ['T1005'],
  'CWE-127': ['T1005'],
  'CWE-129': ['T1190'],
  'CWE-130': ['T1190'],
  'CWE-131': ['T1190'],
  'CWE-134': ['T1059', 'T1190'],
  'CWE-190': ['T1190'],
  'CWE-191': ['T1190'],
  'CWE-193': ['T1190'],
  'CWE-200': ['T1005', 'T1552'],
  'CWE-201': ['T1005'],
  'CWE-209': ['T1005'],
  'CWE-250': ['T1548', 'T1068'],
  'CWE-269': ['T1548', 'T1068'],
  'CWE-270': ['T1548'],
  'CWE-271': ['T1548'],
  'CWE-272': ['T1548'],
  'CWE-273': ['T1548'],
  'CWE-276': ['T1222'],
  'CWE-277': ['T1222'],
  'CWE-278': ['T1222'],
  'CWE-279': ['T1222'],
  'CWE-280': ['T1548'],
  'CWE-281': ['T1222'],
  'CWE-282': ['T1222'],
  'CWE-283': ['T1222'],
  'CWE-284': ['T1190', 'T1078'],
  'CWE-285': ['T1078'],
  'CWE-286': ['T1078'],
  'CWE-287': ['T1078', 'T1556'],
  'CWE-288': ['T1078'],
  'CWE-289': ['T1078'],
  'CWE-290': ['T1553'],
  'CWE-291': ['T1040'],
  'CWE-293': ['T1557'],
  'CWE-294': ['T1111'],
  'CWE-295': ['T1557'],
  'CWE-296': ['T1557'],
  'CWE-297': ['T1557'],
  'CWE-298': ['T1557'],
  'CWE-299': ['T1557'],
  'CWE-300': ['T1557'],
  'CWE-301': ['T1557'],
  'CWE-302': ['T1078'],
  'CWE-303': ['T1078'],
  'CWE-304': ['T1078'],
  'CWE-305': ['T1078'],
  'CWE-306': ['T1078'],
  'CWE-307': ['T1110'],
  'CWE-308': ['T1110'],
  'CWE-309': ['T1110'],
  'CWE-310': ['T1573', 'T1040'],
  'CWE-311': ['T1040'],
  'CWE-312': ['T1552'],
  'CWE-313': ['T1552'],
  'CWE-314': ['T1552'],
  'CWE-315': ['T1552'],
  'CWE-316': ['T1552'],
  'CWE-317': ['T1552'],
  'CWE-318': ['T1552'],
  'CWE-319': ['T1040'],
  'CWE-320': ['T1573'],
  'CWE-321': ['T1552'],
  'CWE-322': ['T1573'],
  'CWE-323': ['T1573'],
  'CWE-324': ['T1573'],
  'CWE-325': ['T1573'],
  'CWE-326': ['T1573'],
  'CWE-327': ['T1573'],
  'CWE-328': ['T1552'],
  'CWE-329': ['T1573'],
  'CWE-330': ['T1573'],
  'CWE-331': ['T1573'],
  'CWE-332': ['T1573'],
  'CWE-333': ['T1573'],
  'CWE-334': ['T1573'],
  'CWE-335': ['T1573'],
  'CWE-336': ['T1573'],
  'CWE-337': ['T1573'],
  'CWE-338': ['T1573'],
  'CWE-339': ['T1573'],
  'CWE-340': ['T1573'],
  'CWE-341': ['T1573'],
  'CWE-342': ['T1573'],
  'CWE-343': ['T1573'],
  'CWE-344': ['T1573'],
  'CWE-345': ['T1553'],
  'CWE-346': ['T1190'],
  'CWE-347': ['T1553'],
  'CWE-348': ['T1190'],
  'CWE-349': ['T1557'],
  'CWE-350': ['T1557'],
  'CWE-351': ['T1190'],
  'CWE-352': ['T1185'],
  'CWE-353': ['T1553'],
  'CWE-354': ['T1553'],
  'CWE-358': ['T1078'],
  'CWE-359': ['T1005'],
  'CWE-362': ['T1203'],
  'CWE-364': ['T1203'],
  'CWE-366': ['T1203'],
  'CWE-367': ['T1203'],
  'CWE-369': ['T1499'],
  'CWE-377': ['T1552'],
  'CWE-378': ['T1552'],
  'CWE-379': ['T1552'],
  'CWE-384': ['T1185'],
  'CWE-400': ['T1499'],
  'CWE-401': ['T1499'],
  'CWE-404': ['T1499'],
  'CWE-405': ['T1499'],
  'CWE-407': ['T1499'],
  'CWE-408': ['T1499'],
  'CWE-409': ['T1499'],
  'CWE-410': ['T1499'],
  'CWE-412': ['T1548'],
  'CWE-413': ['T1548'],
  'CWE-414': ['T1548'],
  'CWE-415': ['T1203'],
  'CWE-416': ['T1203', 'T1211'],
  'CWE-419': ['T1190'],
  'CWE-420': ['T1190'],
  'CWE-421': ['T1190'],
  'CWE-422': ['T1185'],
  'CWE-425': ['T1190'],
  'CWE-426': ['T1574'],
  'CWE-427': ['T1574'],
  'CWE-428': ['T1574'],
  'CWE-434': ['T1190', 'T1105'],
  'CWE-435': ['T1190'],
  'CWE-436': ['T1190'],
  'CWE-437': ['T1190'],
  'CWE-439': ['T1190'],
  'CWE-451': ['T1036'],
  'CWE-454': ['T1190'],
  'CWE-456': ['T1190'],
  'CWE-457': ['T1190'],
  'CWE-459': ['T1070'],
  'CWE-460': ['T1070'],
  'CWE-462': ['T1190'],
  'CWE-463': ['T1190'],
  'CWE-464': ['T1190'],
  'CWE-470': ['T1190'],
  'CWE-471': ['T1565'],
  'CWE-472': ['T1565'],
  'CWE-473': ['T1565'],
  'CWE-474': ['T1565'],
  'CWE-475': ['T1499'],
  'CWE-476': ['T1499'],
  'CWE-477': ['T1190'],
  'CWE-478': ['T1190'],
  'CWE-479': ['T1190'],
  'CWE-480': ['T1190'],
  'CWE-481': ['T1190'],
  'CWE-482': ['T1190'],
  'CWE-483': ['T1190'],
  'CWE-484': ['T1190'],
  'CWE-485': ['T1190'],
  'CWE-486': ['T1190'],
  'CWE-487': ['T1190'],
  'CWE-488': ['T1190'],
  'CWE-489': ['T1190'],
  'CWE-490': ['T1190'],
  'CWE-491': ['T1190'],
  'CWE-492': ['T1190'],
  'CWE-493': ['T1190'],
  'CWE-494': ['T1195', 'T1553'],
  'CWE-495': ['T1553'],
  'CWE-496': ['T1553'],
  'CWE-497': ['T1005'],
  'CWE-498': ['T1005'],
  'CWE-499': ['T1552'],
  'CWE-500': ['T1190'],
  'CWE-501': ['T1565'],
  'CWE-502': ['T1190', 'T1059'],
  'CWE-510': ['T1059'],
  'CWE-511': ['T1059'],
  'CWE-512': ['T1059'],
  'CWE-514': ['T1059'],
  'CWE-515': ['T1059'],
  'CWE-520': ['T1190'],
  'CWE-521': ['T1078', 'T1110'],
  'CWE-522': ['T1552', 'T1555'],
  'CWE-523': ['T1040'],
  'CWE-524': ['T1552'],
  'CWE-525': ['T1552'],
  'CWE-526': ['T1552'],
  'CWE-527': ['T1552'],
  'CWE-528': ['T1552'],
  'CWE-529': ['T1552'],
  'CWE-530': ['T1552'],
  'CWE-531': ['T1552'],
  'CWE-532': ['T1552'],
  'CWE-533': ['T1552'],
  'CWE-534': ['T1552'],
  'CWE-535': ['T1552'],
  'CWE-536': ['T1552'],
  'CWE-537': ['T1552'],
  'CWE-538': ['T1552'],
  'CWE-539': ['T1552'],
  'CWE-540': ['T1552'],
  'CWE-541': ['T1552'],
  'CWE-543': ['T1552'],
  'CWE-544': ['T1552'],
  'CWE-545': ['T1552'],
  'CWE-546': ['T1552'],
  'CWE-547': ['T1552'],
  'CWE-548': ['T1083'],
  'CWE-549': ['T1552'],
  'CWE-550': ['T1190'],
  'CWE-551': ['T1222'],
  'CWE-552': ['T1083'],
  'CWE-553': ['T1190'],
  'CWE-554': ['T1190'],
  'CWE-555': ['T1552'],
  'CWE-556': ['T1552'],
  'CWE-558': ['T1190'],
  'CWE-560': ['T1222'],
  'CWE-561': ['T1190'],
  'CWE-562': ['T1190'],
  'CWE-563': ['T1190'],
  'CWE-564': ['T1190'],
  'CWE-565': ['T1185'],
  'CWE-566': ['T1190'],
  'CWE-567': ['T1190'],
  'CWE-568': ['T1190'],
  'CWE-570': ['T1190'],
  'CWE-571': ['T1190'],
  'CWE-572': ['T1190'],
  'CWE-573': ['T1190'],
  'CWE-574': ['T1190'],
  'CWE-575': ['T1190'],
  'CWE-576': ['T1190'],
  'CWE-577': ['T1190'],
  'CWE-578': ['T1190'],
  'CWE-579': ['T1190'],
  'CWE-580': ['T1190'],
  'CWE-581': ['T1190'],
  'CWE-582': ['T1190'],
  'CWE-583': ['T1190'],
  'CWE-584': ['T1190'],
  'CWE-585': ['T1190'],
  'CWE-586': ['T1190'],
  'CWE-587': ['T1552'],
  'CWE-588': ['T1190'],
  'CWE-589': ['T1190'],
  'CWE-590': ['T1190'],
  'CWE-591': ['T1552'],
  'CWE-592': ['T1552'],
  'CWE-593': ['T1190'],
  'CWE-594': ['T1190'],
  'CWE-595': ['T1190'],
  'CWE-596': ['T1190'],
  'CWE-597': ['T1190'],
  'CWE-598': ['T1552'],
  'CWE-599': ['T1190'],
  'CWE-600': ['T1190'],
  'CWE-601': ['T1598'],
  'CWE-602': ['T1190'],
  'CWE-603': ['T1190'],
  'CWE-605': ['T1190'],
  'CWE-606': ['T1190'],
  'CWE-607': ['T1190'],
  'CWE-608': ['T1190'],
  'CWE-609': ['T1190'],
  'CWE-610': ['T1190'],
  'CWE-611': ['T1190'],
  'CWE-612': ['T1190'],
  'CWE-613': ['T1185'],
  'CWE-614': ['T1185'],
  'CWE-615': ['T1190'],
  'CWE-616': ['T1190'],
  'CWE-617': ['T1499'],
  'CWE-618': ['T1190'],
  'CWE-619': ['T1190'],
  'CWE-620': ['T1110'],
  'CWE-621': ['T1190'],
  'CWE-622': ['T1190'],
  'CWE-623': ['T1190'],
  'CWE-624': ['T1190'],
  'CWE-625': ['T1190'],
  'CWE-626': ['T1190'],
  'CWE-627': ['T1190'],
  'CWE-628': ['T1190'],
  'CWE-636': ['T1190'],
  'CWE-637': ['T1190'],
  'CWE-638': ['T1190'],
  'CWE-639': ['T1190'],
  'CWE-640': ['T1110'],
  'CWE-641': ['T1190'],
  'CWE-642': ['T1565'],
  'CWE-643': ['T1190'],
  'CWE-644': ['T1190'],
  'CWE-645': ['T1190'],
  'CWE-646': ['T1195'],
  'CWE-647': ['T1190'],
  'CWE-648': ['T1190'],
  'CWE-649': ['T1190'],
  'CWE-650': ['T1190'],
  'CWE-651': ['T1190'],
  'CWE-652': ['T1059'],
  'CWE-653': ['T1190'],
  'CWE-654': ['T1190'],
  'CWE-655': ['T1190'],
  'CWE-656': ['T1190'],
  'CWE-657': ['T1190'],
  'CWE-662': ['T1203'],
  'CWE-663': ['T1203'],
  'CWE-664': ['T1190'],
  'CWE-665': ['T1190'],
  'CWE-666': ['T1190'],
  'CWE-667': ['T1203'],
  'CWE-668': ['T1222'],
  'CWE-669': ['T1190'],
  'CWE-670': ['T1190'],
  'CWE-671': ['T1190'],
  'CWE-672': ['T1190'],
  'CWE-673': ['T1190'],
  'CWE-674': ['T1499'],
  'CWE-675': ['T1190'],
  'CWE-676': ['T1190'],
  'CWE-680': ['T1190'],
  'CWE-681': ['T1190'],
  'CWE-682': ['T1190'],
  'CWE-683': ['T1190'],
  'CWE-684': ['T1190'],
  'CWE-685': ['T1190'],
  'CWE-686': ['T1190'],
  'CWE-687': ['T1190'],
  'CWE-688': ['T1190'],
  'CWE-689': ['T1190'],
  'CWE-690': ['T1203'],
  'CWE-691': ['T1190'],
  'CWE-693': ['T1211'],
  'CWE-694': ['T1190'],
  'CWE-695': ['T1190'],
  'CWE-696': ['T1190'],
  'CWE-697': ['T1190'],
  'CWE-698': ['T1190'],
  'CWE-704': ['T1190'],
  'CWE-706': ['T1190'],
  'CWE-707': ['T1190'],
  'CWE-708': ['T1190'],
  'CWE-710': ['T1190'],
  'CWE-732': ['T1222'],
  'CWE-733': ['T1190'],
  'CWE-749': ['T1190'],
  'CWE-754': ['T1190'],
  'CWE-755': ['T1190'],
  'CWE-756': ['T1190'],
  'CWE-757': ['T1557'],
  'CWE-758': ['T1190'],
  'CWE-759': ['T1552'],
  'CWE-760': ['T1552'],
  'CWE-761': ['T1190'],
  'CWE-762': ['T1190'],
  'CWE-763': ['T1190'],
  'CWE-764': ['T1190'],
  'CWE-765': ['T1190'],
  'CWE-766': ['T1190'],
  'CWE-767': ['T1190'],
  'CWE-768': ['T1190'],
  'CWE-769': ['T1499'],
  'CWE-770': ['T1499'],
  'CWE-771': ['T1499'],
  'CWE-772': ['T1499'],
  'CWE-773': ['T1499'],
  'CWE-774': ['T1499'],
  'CWE-775': ['T1499'],
  'CWE-776': ['T1499'],
  'CWE-777': ['T1190'],
  'CWE-778': ['T1070'],
  'CWE-779': ['T1070'],
  'CWE-780': ['T1573'],
  'CWE-781': ['T1190'],
  'CWE-782': ['T1190'],
  'CWE-783': ['T1190'],
  'CWE-784': ['T1185'],
  'CWE-785': ['T1190'],
  'CWE-786': ['T1190'],
  'CWE-787': ['T1203', 'T1190'],
  'CWE-788': ['T1203'],
  'CWE-789': ['T1499'],
  'CWE-790': ['T1190'],
  'CWE-791': ['T1190'],
  'CWE-792': ['T1190'],
  'CWE-793': ['T1190'],
  'CWE-794': ['T1190'],
  'CWE-795': ['T1190'],
  'CWE-796': ['T1190'],
  'CWE-797': ['T1190'],
  'CWE-798': ['T1078', 'T1552'],
  'CWE-799': ['T1499'],
  'CWE-804': ['T1190'],
  'CWE-805': ['T1190'],
  'CWE-806': ['T1190'],
  'CWE-807': ['T1565'],
  'CWE-820': ['T1203'],
  'CWE-821': ['T1203'],
  'CWE-822': ['T1190'],
  'CWE-823': ['T1190'],
  'CWE-824': ['T1190'],
  'CWE-825': ['T1190'],
  'CWE-826': ['T1190'],
  'CWE-827': ['T1190'],
  'CWE-828': ['T1190'],
  'CWE-829': ['T1195'],
  'CWE-830': ['T1190'],
  'CWE-831': ['T1190'],
  'CWE-832': ['T1190'],
  'CWE-833': ['T1499'],
  'CWE-834': ['T1499'],
  'CWE-835': ['T1499'],
  'CWE-836': ['T1190'],
  'CWE-837': ['T1190'],
  'CWE-838': ['T1190'],
  'CWE-839': ['T1190'],
  'CWE-840': ['T1190'],
  'CWE-841': ['T1190'],
  'CWE-842': ['T1190'],
  'CWE-843': ['T1203'],
  'CWE-1021': ['T1185'],
  'CWE-1022': ['T1185'],
  'CWE-1023': ['T1190'],
  'CWE-1024': ['T1190'],
  'CWE-1025': ['T1190'],
  'CWE-1038': ['T1190'],
  'CWE-1039': ['T1190'],
  'CWE-1041': ['T1190'],
  'CWE-1042': ['T1190'],
  'CWE-1043': ['T1190'],
  'CWE-1044': ['T1190'],
  'CWE-1045': ['T1190'],
  'CWE-1046': ['T1190'],
  'CWE-1047': ['T1190'],
  'CWE-1048': ['T1190'],
  'CWE-1049': ['T1190'],
  'CWE-1050': ['T1190'],
  'CWE-1051': ['T1190'],
  'CWE-1052': ['T1190'],
  'CWE-1053': ['T1190'],
  'CWE-1054': ['T1190'],
  'CWE-1055': ['T1190'],
  'CWE-1056': ['T1190'],
  'CWE-1057': ['T1190'],
  'CWE-1058': ['T1190'],
  'CWE-1059': ['T1190'],
  'CWE-1060': ['T1190'],
  'CWE-1061': ['T1190'],
  'CWE-1062': ['T1190'],
  'CWE-1063': ['T1190'],
  'CWE-1064': ['T1190'],
  'CWE-1065': ['T1190'],
  'CWE-1066': ['T1190'],
  'CWE-1067': ['T1190'],
  'CWE-1068': ['T1190'],
  'CWE-1069': ['T1190'],
  'CWE-1070': ['T1190'],
  'CWE-1071': ['T1190'],
  'CWE-1072': ['T1190'],
  'CWE-1073': ['T1190'],
  'CWE-1076': ['T1190'],
  'CWE-1077': ['T1190'],
  'CWE-1078': ['T1190'],
  'CWE-1079': ['T1190'],
  'CWE-1080': ['T1190'],
  'CWE-1082': ['T1190'],
  'CWE-1083': ['T1190'],
  'CWE-1084': ['T1190'],
  'CWE-1085': ['T1190'],
  'CWE-1086': ['T1190'],
  'CWE-1087': ['T1190'],
  'CWE-1088': ['T1190'],
  'CWE-1089': ['T1190'],
  'CWE-1090': ['T1190'],
  'CWE-1091': ['T1190'],
  'CWE-1092': ['T1190'],
  'CWE-1093': ['T1190'],
  'CWE-1094': ['T1190'],
  'CWE-1095': ['T1190'],
  'CWE-1096': ['T1190'],
  'CWE-1097': ['T1190'],
  'CWE-1098': ['T1190'],
  'CWE-1099': ['T1190'],
  'CWE-1100': ['T1190'],
  'CWE-1101': ['T1190'],
  'CWE-1102': ['T1190'],
  'CWE-1103': ['T1190'],
  'CWE-1104': ['T1190'],
  'CWE-1105': ['T1190'],
  'CWE-1106': ['T1190'],
  'CWE-1107': ['T1190'],
  'CWE-1108': ['T1190'],
  'CWE-1109': ['T1190'],
  'CWE-1110': ['T1190'],
  'CWE-1111': ['T1190'],
  'CWE-1112': ['T1190'],
  'CWE-1113': ['T1190'],
  'CWE-1114': ['T1190'],
  'CWE-1115': ['T1190'],
  'CWE-1116': ['T1190'],
  'CWE-1117': ['T1190'],
  'CWE-1118': ['T1190'],
  'CWE-1119': ['T1190'],
  'CWE-1120': ['T1190'],
  'CWE-1121': ['T1190'],
  'CWE-1122': ['T1190'],
  'CWE-1123': ['T1190'],
  'CWE-1124': ['T1190'],
  'CWE-1125': ['T1190'],
  'CWE-1126': ['T1190'],
  'CWE-1127': ['T1190'],
  'CWE-1173': ['T1190'],
  'CWE-1174': ['T1190'],
  'CWE-1175': ['T1190'],
  'CWE-1176': ['T1499'],
  'CWE-1177': ['T1190'],
  'CWE-1178': ['T1190'],
  'CWE-1179': ['T1190'],
  'CWE-1180': ['T1190'],
  'CWE-1181': ['T1190'],
  'CWE-1182': ['T1190'],
  'CWE-1183': ['T1190'],
  'CWE-1184': ['T1190'],
  'CWE-1185': ['T1190'],
  'CWE-1186': ['T1190'],
  'CWE-1187': ['T1190'],
  'CWE-1188': ['T1078'],
  'CWE-1189': ['T1190'],
  'CWE-1190': ['T1190'],
  'CWE-1191': ['T1190'],
  'CWE-1192': ['T1190'],
  'CWE-1193': ['T1190'],
  'CWE-1194': ['T1190'],
  'CWE-1195': ['T1190'],
  'CWE-1196': ['T1190'],
  'CWE-1197': ['T1190'],
  'CWE-1198': ['T1190'],
  'CWE-1199': ['T1190'],
  'CWE-1200': ['T1190'],
  'CWE-1201': ['T1190'],
  'CWE-1202': ['T1190'],
  'CWE-1203': ['T1190'],
  'CWE-1204': ['T1190'],
  'CWE-1205': ['T1190'],
  'CWE-1206': ['T1190'],
  'CWE-1207': ['T1190'],
  'CWE-1208': ['T1190'],
  'CWE-1209': ['T1190'],
  'CWE-1210': ['T1190'],
  'CWE-1211': ['T1190'],
  'CWE-1212': ['T1190'],
  'CWE-1213': ['T1190'],
  'CWE-1214': ['T1190'],
  'CWE-1215': ['T1190'],
  'CWE-1216': ['T1190'],
  'CWE-1217': ['T1190'],
  'CWE-1218': ['T1190'],
  'CWE-1219': ['T1190'],
  'CWE-1220': ['T1190'],
  'CWE-1221': ['T1190'],
  'CWE-1222': ['T1190'],
  'CWE-1223': ['T1190'],
  'CWE-1224': ['T1190'],
  'CWE-1225': ['T1190'],
  'CWE-1226': ['T1190'],
  'CWE-1227': ['T1190'],
  'CWE-1228': ['T1190'],
  'CWE-1229': ['T1190'],
  'CWE-1230': ['T1190'],
  'CWE-1231': ['T1190'],
  'CWE-1232': ['T1190'],
  'CWE-1233': ['T1190'],
  'CWE-1234': ['T1190'],
  'CWE-1235': ['T1190'],
  'CWE-1236': ['T1059'],
  'CWE-1239': ['T1190'],
  'CWE-1240': ['T1573'],
  'CWE-1241': ['T1190'],
  'CWE-1242': ['T1190'],
  'CWE-1243': ['T1190'],
  'CWE-1244': ['T1190'],
  'CWE-1245': ['T1190'],
  'CWE-1246': ['T1190'],
  'CWE-1247': ['T1190'],
  'CWE-1248': ['T1190'],
  'CWE-1249': ['T1190'],
  'CWE-1250': ['T1190'],
  'CWE-1251': ['T1190'],
  'CWE-1252': ['T1190'],
  'CWE-1253': ['T1190'],
  'CWE-1254': ['T1190'],
  'CWE-1255': ['T1190'],
  'CWE-1256': ['T1190'],
  'CWE-1257': ['T1190'],
  'CWE-1258': ['T1190'],
  'CWE-1259': ['T1190'],
  'CWE-1260': ['T1190'],
  'CWE-1261': ['T1190'],
  'CWE-1262': ['T1190'],
  'CWE-1263': ['T1190'],
  'CWE-1264': ['T1190'],
  'CWE-1265': ['T1190'],
  'CWE-1266': ['T1190'],
  'CWE-1267': ['T1190'],
  'CWE-1268': ['T1190'],
  'CWE-1269': ['T1190'],
  'CWE-1270': ['T1190'],
  'CWE-1271': ['T1190'],
  'CWE-1272': ['T1190'],
  'CWE-1273': ['T1190'],
  'CWE-1274': ['T1190'],
  'CWE-1275': ['T1185'],
  'CWE-1276': ['T1190'],
  'CWE-1277': ['T1190'],
  'CWE-1278': ['T1190'],
  'CWE-1279': ['T1190'],
  'CWE-1280': ['T1203'],
  'CWE-1281': ['T1190'],
  'CWE-1282': ['T1190'],
  'CWE-1283': ['T1190'],
  'CWE-1284': ['T1190'],
  'CWE-1285': ['T1190'],
  'CWE-1286': ['T1190'],
  'CWE-1287': ['T1190'],
  'CWE-1288': ['T1190'],
  'CWE-1289': ['T1190'],
  'CWE-1290': ['T1190'],
  'CWE-1291': ['T1190'],
  'CWE-1292': ['T1190'],
  'CWE-1293': ['T1190'],
  'CWE-1294': ['T1190'],
  'CWE-1295': ['T1190'],
  'CWE-1296': ['T1190'],
  'CWE-1297': ['T1190'],
  'CWE-1298': ['T1190'],
  'CWE-1299': ['T1190'],
  'CWE-1300': ['T1190'],
  'CWE-1301': ['T1190'],
  'CWE-1302': ['T1190'],
  'CWE-1303': ['T1190'],
  'CWE-1304': ['T1190'],
  'CWE-1310': ['T1190'],
  'CWE-1311': ['T1190'],
  'CWE-1312': ['T1190'],
  'CWE-1313': ['T1190'],
  'CWE-1314': ['T1190'],
  'CWE-1315': ['T1190'],
  'CWE-1316': ['T1190'],
  'CWE-1317': ['T1190'],
  'CWE-1318': ['T1190'],
  'CWE-1319': ['T1190'],
  'CWE-1320': ['T1190'],
  'CWE-1321': ['T1190'],
  'CWE-1322': ['T1190'],
  'CWE-1323': ['T1190'],
  'CWE-1324': ['T1190'],
  'CWE-1325': ['T1499'],
  'CWE-1326': ['T1190'],
  'CWE-1327': ['T1190'],
  'CWE-1333': ['T1499'],
  'CWE-1334': ['T1190'],
  'CWE-1335': ['T1190'],
  'CWE-1336': ['T1059'],
  'CWE-1338': ['T1190'],
  'CWE-1339': ['T1573'],
  'CWE-1341': ['T1190'],
  'CWE-1342': ['T1190'],
  'CWE-1351': ['T1190'],
  'CWE-1357': ['T1190'],
  'CWE-1384': ['T1190'],
  'CWE-1385': ['T1190'],
  'CWE-1386': ['T1190'],
  'CWE-1389': ['T1190'],
  'CWE-1390': ['T1078'],
  'CWE-1391': ['T1552'],
  'CWE-1392': ['T1078'],
  'CWE-1393': ['T1190'],
  'CWE-1394': ['T1552'],
  'CWE-1395': ['T1190'],
  'CWE-1396': ['T1190'],
  'CWE-1420': ['T1190'],
  'CWE-1421': ['T1005'],
  'CWE-1422': ['T1005'],
  'CWE-1423': ['T1005'],
  'CWE-1424': ['T1005'],
  'CWE-NVD-CWE-noinfo': ['T1190'],
  'CWE-NVD-CWE-Other': ['T1190'],
};

export function mapCwesToAttackIds(cwes: string[]): string[] {
  const attackIds = new Set<string>();
  for (const cwe of cwes) {
    const mapped = CWE_TO_ATTACK[cwe];
    if (mapped) mapped.forEach(id => attackIds.add(id));
  }
  return [...attackIds];
}

@Injectable({ providedIn: 'root' })
export class CveService {
  private readonly NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

  private searchResultsSubject = new BehaviorSubject<NvdCveItem[]>([]);
  private activeCveSubject = new BehaviorSubject<NvdCveItem | null>(null);
  private loadingSubject = new BehaviorSubject<boolean>(false);
  private errorSubject = new BehaviorSubject<string | null>(null);
  private kevMapSubject = new BehaviorSubject<Map<string, KevEntry>>(new Map());
  private kevLoadedSubject = new BehaviorSubject<boolean>(false);
  // Map of attackId -> number of KEV CVEs mapped to it
  private kevTechScoresSubject = new BehaviorSubject<Map<string, number>>(new Map());

  searchResults$: Observable<NvdCveItem[]> = this.searchResultsSubject.asObservable();
  activeCve$: Observable<NvdCveItem | null> = this.activeCveSubject.asObservable();
  loading$: Observable<boolean> = this.loadingSubject.asObservable();
  error$: Observable<string | null> = this.errorSubject.asObservable();
  kevLoaded$: Observable<boolean> = this.kevLoadedSubject.asObservable();
  kevTechScores$: Observable<Map<string, number>> = this.kevTechScoresSubject.asObservable();

  /** Emits true once KEV data AND the CTID ATT&CK→CVE data are both loaded. */
  ctidKevReady$: Observable<boolean>;

  constructor(private http: HttpClient, private attackCveService: AttackCveService) {
    this.ctidKevReady$ = combineLatest([
      this.kevLoadedSubject,
      this.attackCveService.loaded$,
    ]).pipe(map(([kevLoaded, ctidLoaded]) => kevLoaded && ctidLoaded));
  }

  loadKev(): void {
    if (this.kevLoadedSubject.value) return;
    // CISA.gov doesn't send CORS headers — route through allorigins proxy.
    // Fallback chain: allorigins proxy → direct CISA (may work in production) → empty.
    const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(this.KEV_URL)}`;
    this.http.get<any>(proxyUrl).pipe(
      catchError(() => this.http.get<any>(this.KEV_URL)),
      catchError(() => of({ vulnerabilities: [] }))
    ).subscribe((data: any) => {
      const vulns: KevEntry[] = data.vulnerabilities ?? [];
      const map = new Map<string, KevEntry>();
      for (const v of vulns) {
        map.set(v.cveID, v);
      }
      this.kevMapSubject.next(map);
      this.kevLoadedSubject.next(true);
      this.computeKevTechScores(vulns);
    });
  }

  /**
   * Builds technique→count scores from CTID direct CVE→ATT&CK mappings for a list of KEV CVE IDs.
   * Returns a Map of techniqueAttackId → number of KEV CVEs that map to it via CTID data.
   */
  getKevScoresFromCtid(kevCveIds: string[]): Map<string, number> {
    const scores = new Map<string, number>();
    for (const cveId of kevCveIds) {
      const mapping = this.attackCveService.getMappingForCve(cveId);
      if (!mapping) continue;
      const allTechs = [
        ...new Set([
          ...mapping.primaryImpact,
          ...mapping.secondaryImpact,
          ...mapping.exploitationTechnique,
        ]),
      ];
      for (const techId of allTechs) {
        scores.set(techId, (scores.get(techId) ?? 0) + 1);
      }
    }
    return scores;
  }

  private computeKevTechScores(vulns: KevEntry[]): void {
    // CWE-based scores (indirect)
    const cweScores = new Map<string, number>();
    for (const v of vulns) {
      const cwes = v.cwes ? v.cwes.split(',').map((c: string) => c.trim()).filter(Boolean) : [];
      const attackIds = mapCwesToAttackIds(cwes.length > 0 ? cwes : ['CWE-NVD-CWE-noinfo']);
      for (const id of attackIds) {
        cweScores.set(id, (cweScores.get(id) ?? 0) + 1);
      }
    }

    // CTID-based scores (direct) — only available if AttackCveService has loaded
    const kevCveIds = vulns.map(v => v.cveID);
    const ctidScores = this.getKevScoresFromCtid(kevCveIds);

    // Merge: take the max of each source so CTID data can only raise a score, not lower it
    const merged = new Map<string, number>(cweScores);
    for (const [techId, ctidCount] of ctidScores) {
      merged.set(techId, Math.max(merged.get(techId) ?? 0, ctidCount));
    }

    this.kevTechScoresSubject.next(merged);
  }

  searchCves(query: string): void {
    if (!query.trim()) return;
    this.loadingSubject.next(true);
    this.errorSubject.next(null);

    const isCveId = /^CVE-\d{4}-\d+$/i.test(query.trim());
    const params = isCveId
      ? `cveId=${encodeURIComponent(query.trim().toUpperCase())}`
      : `keywordSearch=${encodeURIComponent(query.trim())}&resultsPerPage=20`;

    this.http.get<any>(`${this.NVD_API}?${params}`).pipe(
      catchError(err => {
        this.errorSubject.next('NVD API error: ' + (err.message ?? 'network error'));
        this.loadingSubject.next(false);
        return of(null);
      })
    ).subscribe((data: any) => {
      this.loadingSubject.next(false);
      if (!data) return;
      const items = (data.vulnerabilities ?? []).map((v: any) => this.parseNvdItem(v.cve));
      this.searchResultsSubject.next(items);
    });
  }

  selectCve(cve: NvdCveItem | null): void {
    this.activeCveSubject.next(cve);
  }

  clearResults(): void {
    this.searchResultsSubject.next([]);
    this.activeCveSubject.next(null);
  }

  /** Reverse-lookup: given an ATT&CK technique ID, return all CWE IDs that map to it */
  getAttackToCweIds(attackId: string): string[] {
    const result: string[] = [];
    for (const [cwe, attacks] of Object.entries(CWE_TO_ATTACK)) {
      if (attacks.includes(attackId)) result.push(cwe);
    }
    return result;
  }

  /** Fetch CVEs from NVD for all CWEs associated with a technique. Batches serially to respect rate limits.
   *  Uses the apiKey from settings if provided (via apiKey parameter). */
  fetchNvdCvesByAttackId(
    attackId: string,
    apiKey = '',
  ): Observable<{ items: NvdCveItem[]; cwesFetched: string[]; totalResults: number }> {
    const cwes = this.getAttackToCweIds(attackId);
    if (cwes.length === 0) {
      return of({ items: [], cwesFetched: [], totalResults: 0 });
    }
    // Limit to first 5 most specific CWEs to avoid overwhelming NVD
    const targetCwes = cwes.slice(0, 5);
    const headers: Record<string, string> = apiKey ? { 'apiKey': apiKey } : {};

    // Serial requests to avoid rate limiting
    return new Observable(observer => {
      const allItems = new Map<string, NvdCveItem>();
      let idx = 0;
      const fetchNext = () => {
        if (idx >= targetCwes.length) {
          observer.next({ items: [...allItems.values()], cwesFetched: targetCwes, totalResults: allItems.size });
          observer.complete();
          return;
        }
        const cwe = targetCwes[idx++];
        // NVD CWE ID format is just "CWE-78" or the number part
        const cweParam = cwe.startsWith('CWE-') ? cwe : `CWE-${cwe}`;
        const url = `${this.NVD_API}?cweId=${encodeURIComponent(cweParam)}&resultsPerPage=100`;
        this.http.get<any>(url, { headers }).pipe(
          catchError(() => of({ vulnerabilities: [] }))
        ).subscribe(data => {
          const items = (data?.vulnerabilities ?? []).map((v: any) => this.parseNvdItem(v.cve));
          for (const item of items) {
            if (!allItems.has(item.id)) allItems.set(item.id, item);
          }
          // Delay 300ms between requests to stay under NVD rate limit
          setTimeout(fetchNext, apiKey ? 100 : 300);
        });
      };
      fetchNext();
    });
  }

  isKev(cveId: string): boolean {
    return this.kevMapSubject.value.has(cveId);
  }

  getKevEntry(cveId: string): KevEntry | undefined {
    return this.kevMapSubject.value.get(cveId);
  }

  private parseNvdItem(cve: any): NvdCveItem {
    const metrics = cve.metrics ?? {};
    const cvssData = metrics.cvssMetricV31?.[0]?.cvssData
      ?? metrics.cvssMetricV30?.[0]?.cvssData
      ?? metrics.cvssMetricV2?.[0]?.cvssData
      ?? null;

    const cwes: string[] = [];
    for (const w of (cve.weaknesses ?? [])) {
      for (const d of (w.description ?? [])) {
        if (d.value && d.value !== 'NVD-CWE-noinfo' && d.value !== 'NVD-CWE-Other') {
          cwes.push(d.value);
        } else if (d.value) {
          cwes.push('CWE-' + d.value.replace('NVD-', ''));
        }
      }
    }

    const cpes: string[] = [];
    for (const config of (cve.configurations ?? [])) {
      for (const node of (config.nodes ?? [])) {
        for (const match of (node.cpeMatch ?? [])) {
          if (match.vulnerable) cpes.push(match.criteria);
        }
      }
    }

    const mappedAttackIds = mapCwesToAttackIds(cwes.length > 0 ? cwes : ['CWE-NVD-CWE-noinfo']);
    const kevEntry = this.kevMapSubject.value.get(cve.id);

    return {
      id: cve.id,
      description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? '',
      cvssScore: cvssData?.baseScore ?? null,
      cvssVector: cvssData?.vectorString ?? null,
      severity: (cvssData?.baseSeverity ?? 'UNKNOWN') as NvdCveItem['severity'],
      cwes,
      cpes: cpes.slice(0, 20),
      published: cve.published ?? '',
      lastModified: cve.lastModified ?? '',
      references: (cve.references ?? []).slice(0, 10).map((r: any) => ({ url: r.url, tags: r.tags ?? [] })),
      mappedAttackIds,
      isKev: !!kevEntry,
      kevDateAdded: kevEntry?.dateAdded,
      kevDueDate: kevEntry?.dueDate,
      kevVendorProject: kevEntry?.vendorProject,
      kevProduct: kevEntry?.product,
      kevKnownRansomware: kevEntry?.knownRansomwareCampaignUse === 'Known',
    };
  }
}
