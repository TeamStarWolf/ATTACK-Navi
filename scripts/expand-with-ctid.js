#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
/**
 * Expands CWE_TO_ATTACK using the CTID's own capability_group → technique table
 * extracted from the KEV Mappings Explorer (155 unique techniques).
 * Then re-runs the NVD scan with the massively expanded technique coverage.
 */
const fs = require("fs");
const path = require("path");

// CWE → CTID capability group mapping
const CWE_TO_GROUP = {
  "89": "sql_injection", "564": "sql_injection",
  "77": "command_injection", "78": "command_injection", "88": "command_injection",
  "94": "code_injection", "95": "code_injection", "96": "code_injection", "1321": "code_injection", "1236": "code_injection",
  "79": "xss", "80": "xss", "81": "xss", "82": "xss", "83": "xss", "84": "xss", "85": "xss", "86": "xss", "87": "xss",
  "119": "buffer_overflow", "120": "buffer_overflow", "121": "buffer_overflow", "122": "buffer_overflow", "131": "buffer_overflow", "680": "buffer_overflow", "805": "buffer_overflow", "806": "buffer_overflow",
  "125": "oob", "787": "oob", "786": "oob", "788": "oob",
  "416": "use_after_free", "415": "use_after_free",
  "190": "int_overflow", "191": "int_overflow", "193": "int_overflow",
  "843": "type_confusion",
  "476": "pointer_deref", "824": "pointer_vuln", "825": "pointer_vuln",
  "22": "dir_traversal", "23": "dir_traversal", "24": "dir_traversal", "25": "dir_traversal", "59": "dir_traversal", "61": "dir_traversal",
  "287": "auth_bypass", "288": "auth_bypass", "289": "auth_bypass", "294": "auth_bypass", "302": "auth_bypass", "303": "auth_bypass", "304": "auth_bypass", "305": "auth_bypass",
  "306": "auth_missing", "862": "auth_missing",
  "284": "access_ctrl", "285": "access_ctrl", "863": "access_ctrl", "639": "access_ctrl",
  "269": "priv_escalation", "250": "priv_escalation", "268": "priv_escalation",
  "276": "priv_mgmt", "732": "priv_mgmt", "281": "priv_mgmt",
  "798": "hardcoded_creds", "259": "hardcoded_creds", "321": "hardcoded_creds", "312": "hardcoded_creds", "319": "hardcoded_creds", "522": "hardcoded_creds", "256": "hardcoded_creds",
  "918": "ssrf", "611": "xxe", "776": "xxe", "434": "unrestricted_upload", "502": "untrusted_data",
  "20": "input_validation", "129": "input_validation", "130": "input_validation",
  "400": "dos", "770": "dos", "835": "dos", "674": "dos",
  "362": "race_condition", "367": "race_condition",
  "290": "spoofing_vuln", "345": "spoofing_vuln", "346": "spoofing_vuln", "347": "spoofing_vuln", "352": "spoofing_vuln",
  "693": "feature_bypass", "74": "inject", "91": "inject", "93": "inject", "113": "inject",
  "401": "memory_mgmt", "404": "resource_mgmt", "459": "resource_mgmt",
  "16": "default_cfg", "265": "sandbox_bypass", "98": "code_execution", "134": "code_execution"
};

// CTID group → ATT&CK techniques (from KEV Mappings Explorer)
const GROUP_TO_TECHS = {
  "access_ctrl": ["T1003.003","T1003.008","T1005","T1007","T1021.001","T1033","T1056","T1059","T1059.003","T1059.004","T1059.007","T1068","T1078","T1078.003","T1078.004","T1082","T1083","T1090.001","T1105","T1133","T1136","T1190","T1195","T1199","T1202","T1203","T1212","T1486","T1505","T1530","T1552","T1552.001","T1592","T1601"],
  "auth_bypass": ["T1003","T1003.003","T1005","T1018","T1021","T1027","T1040","T1046","T1047","T1055","T1059","T1059.003","T1068","T1069","T1070.004","T1071.001","T1078","T1087","T1087.002","T1098","T1098.004","T1105","T1136","T1140","T1190","T1203","T1210","T1213","T1218","T1485","T1495","T1496","T1499","T1505.003","T1548","T1555","T1556","T1557","T1557.001","T1560.001","T1565.001","T1567","T1571","T1573.001","T1574","T1608.001"],
  "auth_missing": ["T1021.004","T1059","T1059.003","T1087","T1087.001","T1133","T1190","T1203","T1486","T1548","T1555"],
  "buffer_overflow": ["T1003","T1003.001","T1005","T1018","T1027","T1041","T1046","T1048","T1055","T1059","T1059.004","T1059.007","T1068","T1070.004","T1071.001","T1078","T1105","T1133","T1134.001","T1136","T1189","T1190","T1203","T1204","T1204.001","T1204.002","T1497","T1498","T1499","T1543","T1565","T1574","T1584.005","T1588.006","T1595","T1608.001","T1622"],
  "code_execution": ["T1003","T1003.003","T1005","T1021.001","T1027","T1036","T1041","T1046","T1047","T1048","T1048.003","T1053","T1053.005","T1059","T1059.001","T1059.004","T1059.007","T1068","T1070","T1070.001","T1070.004","T1071","T1071.001","T1078","T1083","T1087","T1087.002","T1090","T1105","T1110","T1112","T1114","T1133","T1136","T1136.001","T1140","T1189","T1190","T1203","T1204","T1204.001","T1204.002","T1210","T1218","T1482","T1485","T1486","T1489","T1490","T1496","T1498","T1499","T1499.002","T1505.003","T1530","T1542.005","T1543","T1552","T1553.005","T1560.001","T1562.001","T1566","T1567","T1569.002","T1573.001","T1574","T1608.001"],
  "code_injection": ["T1055","T1059","T1059.003","T1068","T1087.002","T1105","T1190","T1195.002","T1203","T1486","T1543","T1574"],
  "command_execution": ["T1011","T1055","T1059","T1190","T1608.001"],
  "command_injection": ["T1003","T1003.001","T1005","T1021.004","T1033","T1041","T1053","T1055","T1059","T1059.003","T1059.004","T1068","T1070","T1071.001","T1078","T1106","T1112","T1133","T1190","T1203","T1496","T1498","T1505","T1505.003","T1543","T1548","T1552","T1570","T1584.005","T1588"],
  "default_cfg": ["T1005","T1068","T1078","T1133","T1212","T1557"],
  "dir_traversal": ["T1003","T1005","T1037","T1041","T1049","T1059","T1068","T1083","T1087","T1087.002","T1105","T1119","T1190","T1202","T1210","T1496","T1505.003","T1550.002","T1552.001","T1552.004","T1555","T1558","T1565.001","T1574","T1592","T1608.001"],
  "dos": ["T1005","T1037","T1190","T1202","T1498","T1608.001","T1653"],
  "feature_bypass": ["T1001","T1059","T1105","T1106","T1189","T1203","T1204.002","T1548.002","T1553.005","T1557","T1562","T1565","T1566.001","T1566.002","T1588.001"],
  "hardcoded_creds": ["T1059","T1106","T1203","T1552","T1552.001"],
  "inject": ["T1059","T1059.004","T1090","T1133","T1190","T1202","T1221","T1496","T1505.003"],
  "input_validation": ["T1005","T1027","T1041","T1059","T1068","T1105","T1189","T1190","T1203","T1204.001","T1204.002","T1213","T1497","T1566.001"],
  "int_overflow": ["T1059","T1091","T1105","T1189","T1204.001","T1486","T1574"],
  "memory_corruption": ["T1001","T1055","T1059","T1059.007","T1105","T1106","T1189","T1203","T1204.002","T1495","T1499.004","T1557","T1562","T1566.001"],
  "memory_mgmt": ["T1204.002"],
  "oob": ["T1005","T1011","T1055","T1059","T1068","T1078","T1091","T1105","T1189","T1190","T1203","T1204.002","T1499","T1499.004","T1547.009","T1555","T1574","T1588.001","T1611"],
  "pointer_deref": ["T1189"],
  "pointer_vuln": ["T1059.007","T1204.002"],
  "priv_escalation": ["T1003","T1016","T1021","T1027","T1037","T1055.012","T1059","T1059.003","T1068","T1071.001","T1078","T1082","T1087.002","T1110","T1133","T1136","T1136.001","T1190","T1203","T1204.002","T1211","T1222","T1485","T1486","T1490","T1543","T1547.001","T1548.001","T1550.002","T1562","T1566","T1566.001","T1573.001","T1574","T1598.002"],
  "priv_mgmt": ["T1059","T1068","T1078","T1112","T1133","T1203"],
  "race_condition": ["T1059.007","T1203"],
  "resource_mgmt": ["T1005","T1011","T1078","T1091","T1190"],
  "sandbox_bypass": ["T1068","T1203","T1497","T1548"],
  "spoofing_vuln": ["T1189","T1204.001","T1555","T1566"],
  "sql_injection": ["T1005","T1055","T1059","T1059.004","T1068","T1082","T1105","T1136","T1190","T1485","T1486","T1531"],
  "ssrf": ["T1005","T1046","T1059","T1059.007","T1078","T1190","T1505.003","T1547","T1555","T1566.002"],
  "type_confusion": ["T1005","T1059","T1105","T1189","T1203","T1204.002","T1566.001"],
  "unrestricted_upload": ["T1055","T1059","T1068","T1078","T1190","T1202","T1491.002","T1496","T1505.003","T1602"],
  "untrusted_data": ["T1003.001","T1036.005","T1041","T1046","T1053.005","T1059","T1059.004","T1059.007","T1068","T1071.001","T1071.002","T1078","T1105","T1133","T1190","T1202","T1203","T1484.001","T1486","T1496","T1505.003"],
  "use_after_free": ["T1003","T1003.001","T1005","T1041","T1055.001","T1059","T1059.007","T1068","T1071.001","T1105","T1112","T1189","T1190","T1203","T1204.001","T1204.002","T1219","T1543","T1566.002","T1574","T1608.001"],
  "xss": ["T1041","T1055","T1056","T1059","T1059.004","T1059.007","T1082","T1098","T1114","T1114.002","T1185","T1189","T1190","T1204.001","T1217","T1566","T1566.002","T1567"],
  "xxe": ["T1003","T1005","T1046","T1059","T1078","T1190"]
};

// Load existing CWE_TO_ATTACK
const svcPath = path.join(__dirname, "..", "src", "app", "services", "cve.service.ts");
const svcSrc = fs.readFileSync(svcPath, "utf8");
const CWE_TO_ATTACK = {};
for (const m of svcSrc.matchAll(/'CWE-(\d+)':\s*\[([^\]]*)\]/g)) {
  CWE_TO_ATTACK[m[1]] = m[2].match(/'([^']+)'/g)?.map(s => s.replace(/'/g, "")) || [];
}

const origTechs = new Set(Object.values(CWE_TO_ATTACK).flat());
console.log("Before:", Object.keys(CWE_TO_ATTACK).length, "CWEs ->", origTechs.size, "techniques");

// Expand using CTID groups
let added = 0;
for (const [cwe, group] of Object.entries(CWE_TO_GROUP)) {
  const groupTechs = GROUP_TO_TECHS[group] || [];
  if (!CWE_TO_ATTACK[cwe]) CWE_TO_ATTACK[cwe] = [];
  for (const t of groupTechs) {
    if (!CWE_TO_ATTACK[cwe].includes(t)) {
      CWE_TO_ATTACK[cwe].push(t);
      added++;
    }
  }
}

const newTechs = new Set(Object.values(CWE_TO_ATTACK).flat());
console.log("After:", Object.keys(CWE_TO_ATTACK).length, "CWEs ->", newTechs.size, "techniques");
console.log("Added", added, "new CWE->technique links");

// Write back to cve.service.ts
const lines = [];
for (const cwe of Object.keys(CWE_TO_ATTACK).sort((a, b) => Number(a) - Number(b))) {
  const techs = CWE_TO_ATTACK[cwe].map(t => "'" + t + "'").join(", ");
  lines.push("  'CWE-" + cwe + "':  [" + techs + "],");
}
const newMapStr = "export const CWE_TO_ATTACK: Record<string, string[]> = {\n" + lines.join("\n") + "\n};";
const newSrc = svcSrc.replace(/export const CWE_TO_ATTACK[^{]*\{[\s\S]*?\n\};/, newMapStr);
fs.writeFileSync(svcPath, newSrc);
console.log("Updated cve.service.ts with CTID-expanded mapping");
console.log("\nNew techniques:", [...newTechs].filter(t => !origTechs.has(t)).sort().join(", "));
console.log("\nNow re-run: node scripts/fetch-all-cves.js");
