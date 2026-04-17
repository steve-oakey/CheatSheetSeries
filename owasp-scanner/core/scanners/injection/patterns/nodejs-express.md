# Injection Patterns: Node.js / Express

## Dangerous SQL Sinks

### Raw Query Construction
```
\.query\(.*\$\{|\.query\(.*\+           # pg/mysql query with template literal or concat
db\.query\(.*\+.*req\.|pool\.query\(.*\+ # DB query with request data
connection\.query\(.*\+.*req\.body       # MySQL query with body concat
\.raw\(.*\$\{|\.raw\(.*\+               # Knex/Sequelize raw with interpolation
sequelize\.query\(.*\$\{                 # Sequelize raw query with template literal
knex\.raw\(.*\$\{|knex\.raw\(.*\+       # Knex raw with interpolation
```

### Sequelize Unsafe Methods
```
sequelize\.query\(.*\+                   # Raw query with concatenation
\[Op\.eq\].*req\.\w+\[|\.where\(.*req\.  # Operator injection from user input
Sequelize\.literal\(.*req\.|Sequelize\.literal\(.*\$\{ # Literal with user input
\.findAll\(\{.*where:.*req\.query        # Direct req.query in where (review)
```

### TypeORM Unsafe Methods
```
\.query\(.*\$\{|\.query\(.*\+           # Raw query with interpolation
createQueryBuilder\(.*\.where\(.*\$\{   # QueryBuilder with interpolation
getRepository\(.*\.query\(.*\+          # Repository raw query with concat
```

### Safe: Parameterized queries
```
\.query\(.*\$\d|\.query\(.*\?           # Parameterized placeholder (good)
\.query\(.*,\s*\[                        # Parameterized array (good)
\.where\(\{.*\}\)                        # ORM where object (good)
\.findOne\(\{.*where:                    # ORM findOne (good, review values)
knex\(\w+\)\.where\(                     # Knex query builder (good)
```

## NoSQL Injection

### Dangerous: MongoDB query injection
```
\.find\(.*req\.body|\.find\(\{.*req\.query # MongoDB find with raw request data
\.findOne\(.*req\.body                   # findOne with raw request
\.updateOne\(.*req\.body                 # update with raw request body
\.deleteOne\(.*req\.body                 # delete with raw request body
\$where.*req\.|where.*function.*req\.    # $where with user input (code execution)
\$regex.*req\.\w+\[                      # $regex with user input
```

### Safe: Validated MongoDB queries
```
\.find\(\{.*:\s*(req\.params\.\w+|sanitize) # Parameterized find (good)
mongoose\.Schema\(                       # Mongoose schema validation (good)
\.lean\(\)                               # Lean queries (good, reduces overhead)
mongo-sanitize|express-mongo-sanitize    # Sanitization library (good)
```

## OS Command Injection

### Dangerous: Shell execution with user input
```
child_process\.exec\(.*req\.|exec\(.*req\. # exec with request data
child_process\.execSync\(.*req\.         # execSync with request data
exec\(.*\$\{.*req\.|exec\(.*\+.*req\.   # exec with template literal or concat
require\(["']child_process["']\)\.exec\(.*\+ # child_process with concat
shelljs\.\w+\(.*req\.|shell\.exec\(.*req\. # shelljs with request data
```

### Safe: Array-based command execution
```
child_process\.execFile\(                # execFile (no shell, good)
child_process\.spawn\(.*\{.*shell:\s*false # spawn without shell (good)
child_process\.spawn\(\w+,\s*\[         # spawn with args array (good)
execa\(                                  # execa library (good, no shell by default)
```

## Prototype Pollution

### Dangerous: Recursive merge with user input
```
Object\.assign\(\{\},.*req\.body         # Object.assign with request body (review)
_\.merge\(|_\.defaultsDeep\(|_\.set\(   # Lodash deep merge (CVE-prone)
merge\(.*req\.body|deepMerge\(.*req\.    # Deep merge with user input
\[req\.body\.\w+\]|obj\[req\.\w+\[      # Bracket notation with user key
JSON\.parse\(.*req\.|JSON\.parse\(.*body # JSON parse of user input (check proto)
```

### Safe: Prototype pollution prevention
```
Object\.create\(null\)                   # Null prototype object (good)
Object\.freeze\(                         # Frozen object (good)
hasOwnProperty\.call\(|\.hasOwn\(       # Own property check (good)
new Map\(\)                              # Map instead of plain object (good)
```

## Server-Side Template Injection (SSTI)

### Dangerous: Dynamic template compilation
```
ejs\.render\(.*req\.|ejs\.compile\(.*req\. # EJS with user input in template
pug\.render\(.*req\.|pug\.compile\(.*req\. # Pug with user input
nunjucks\.renderString\(.*req\.          # Nunjucks renderString with user input
handlebars\.compile\(.*req\.             # Handlebars compile with user input
```

### Safe: Template file rendering
```
res\.render\(["']                        # File-based rendering (good)
nunjucks\.render\(["']                   # File-based Nunjucks (good)
```

## Path Traversal

### Dangerous: User-controlled file paths
```
fs\.readFileSync\(.*req\.|fs\.readFile\(.*req\. # File read with user input
path\.join\(.*req\.\w+\[|path\.join\(.*req\.params # Path join with user input
path\.resolve\(.*req\.                   # Path resolve with user input
res\.sendFile\(.*req\.|res\.download\(.*req\. # Send/download with user input
createReadStream\(.*req\.                # Stream with user input
```

### Safe: Path traversal prevention
```
path\.basename\(                         # Basename extraction (good)
path\.normalize\(.*\.startsWith\(        # Normalize + prefix check (good)
express\.static\(                        # Static file serving (good)
```

## XML/XXE (Express)

### Dangerous: Unsafe XML parsing
```
xml2js\.parseString\(|libxmljs\.parseXml\( # XML parsing (review config)
xmldom.*DOMParser\(                      # xmldom parser (review)
```

### Safe: Secure XML parsing
```
xml2js.*explicitRoot|xml2js.*strict      # xml2js with options (good)
fast-xml-parser                          # Fast XML parser (no XXE by default, good)
```

## Deserialization

### Dangerous: Unsafe deserialization
```
node-serialize.*unserialize\(           # node-serialize (known RCE)
serialize-javascript.*eval\(            # eval of serialized data
vm\.runInNewContext\(.*req\.|vm\.runInContext\(.*req\. # VM with user input
new Function\(.*req\.|Function\(.*req\. # Function constructor with user input
```

### Safe: JSON-based deserialization
```
JSON\.parse\(                            # JSON parsing (good, check proto pollution)
ajv\.validate\(|joi\.validate\(          # Schema validation (good)
```

## XPath Injection (RULE-INJ-015)

### Dangerous: XPath with user input
```
xpath\.select\(.*\$\{|xpath\.select\(.*\+ # XPath with interpolation
xpath\.evaluate\(.*req\.|xpath\.\w+\(.*\+ # XPath with user input
xmldom.*evaluate\(.*\+                   # xmldom XPath with concat
```

## Stored Procedure Calls (RULE-INJ-014)

### Dangerous: Dynamic stored procedure calls
```
\.query\(["']CALL.*\$\{|\.query\(["']EXEC.*\+ # CALL/EXEC with interpolation
\.query\(["']EXECUTE.*\$\{              # EXECUTE with interpolation
```

### Safe: Parameterized procedure calls
```
\.query\(["']CALL.*\?|\.query\(["']EXEC.*\? # Parameterized procedure (good)
\.execute\(.*,\s*\[                      # Parameterized with array (good)
```
