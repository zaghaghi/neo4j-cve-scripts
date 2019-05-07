CALL graphql.idl('
type CVE {
  id: ID!
  name: String
  description: [String]
  published: String
  productVersions: [ProductVersion]
    @relation(name:"AFFECTS", direction: "OUT")
  products: [Product]
    @cypher(
      statement: "MATCH (this)-[:AFFECTS]->(:ProductVersion)-[:VERSION_OF]->(p:Product) RETURN p"
    )
  problems: [CWE] @relation(name:"PROBLEM_TYPE", direction: "OUT")
  references: [Reference] @relation(name:"REFERENCE", direction: "OUT")
  cvss2: CVSS2 @relation(name:"SCORED", direction: "OUT")
  cvss3: CVSS3 @relation(name:"SCORED", direction: "OUT")
}

type CVSS2 {
  id: ID!
  name: String
  access_complexity: String
  authentication: String
  availability_impact: String
  base_score: Float
  confidentiality_impact: String
  exploitability_score: Float
  impact_score: Int
  integrity_impact: String
  severity: String
  obtain_all_privilege: Boolean
  obtain_other_privilege: Boolean
  obtain_user_privilege: Boolean
  user_interaction_required: Boolean
  vector_string: String
  access_vector: String
  cve: CVE @relation(name:"SCORED", direction: "IN")
}

type CVSS3 {
  id: ID!
  name: String
  attack_complexity: String
  availability_impact: String
  base_score: Float
  base_severity: String
  confidentiality_impact: String
  exploitability_score: Float
  impact_score: Float
  integrity_impact: String
  privileges_required: String
  scope: String
  user_interaction: String
  vector_string: String
  attack_vector: String
  cve: CVE @relation(name:"SCORED", direction: "IN")
}

type ProductVersion {
  id: ID!
  name: String
  version_value: String
  product: Product @relation(name: "VERSION_OF", direction: "OUT")
  cves: [CVE]
    @relation(name:"AFFECTS", direction: "IN")
}

type Product {
  id: ID!
  name: String
  versions: [ProductVersion] @relation(name: "VERSION_OF", direction: "IN")
  vendor: Vendor @relation(name: "MADE_BY", direction: "OUT")
}

type Vendor {
  id: ID!
  name: String
  products: [Product] @relation(name: "MADE_BY", direction: "IN")
}

type CWE {
  id: ID!
  name: String
  title: String
  abstraction: String
  status: String
  description: String
  functional_areas: String
  affected_resources: String
  cves: [CVE] @relation(name:"PROBLEM_TYPE", direction:"IN")
}

type Reference {
  id: ID!
  url: String
  name: String
  source: String
}

');