type t = { schema : string; checksum : string; policy : Ir.t }

let schema = "lpf.plan.v1"

let of_ir policy =
  { schema; checksum = Ir_json.checksum_of_ir schema policy; policy }

let checksum plan = plan.checksum

let to_json plan =
  Json_util.field_object
    [
      ("schema", Json_util.string plan.schema);
      ("kind", Json_util.string "semantic-policy");
      ("checksum", Json_util.string plan.checksum);
      ( "policy",
        Ir_json.policy_json ~include_spans:true ~for_checksum:false plan.policy
      );
    ]
  ^ "\n"
