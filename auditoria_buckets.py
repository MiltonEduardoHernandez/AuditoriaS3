import boto3
import botocore.exceptions
import json
import csv
import os

# Usamos solo este perfil para la prueba
profiles = ["datalab-dev"]

# Carpeta de salida
output_folder = "salida_politicas"
os.makedirs(output_folder, exist_ok=True)

# CSV de salida
csv_file = os.path.join(output_folder, "buckets_con_politicas_s3.csv")
with open(csv_file, mode="w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Bucket", "aws:userid detectado", "Acciones"])  # Eliminamos "Perfil"

    for profile in profiles:
        print(f"🔍 Revisando perfil: {profile}")
        session = boto3.Session(profile_name=profile)
        s3 = session.client("s3")

        try:
            buckets = s3.list_buckets()["Buckets"]
        except Exception as e:
            print(f"❌ Error al listar buckets para el perfil {profile}: {e}")
            continue

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                policy_raw = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
                policy = json.loads(policy_raw)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    continue  # Bucket sin política, lo ignoramos
                else:
                    print(f"⚠️ Error al obtener la política del bucket {bucket_name}: {e}")
                    continue

            # Acumular acciones y aws:userid para el bucket
            all_actions = set()
            all_userids = set()

            for stmt in policy.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                action_set = set(actions)

                # ✅ Revisar si hay al menos una acción relacionada con S3
                if not any(action.startswith("s3:") for action in action_set):
                    continue

                # Acumular acciones
                all_actions.update(action_set)

                # 🔎 Buscar aws:userid si existe
                condition = stmt.get("Condition", {})
                for cond_type in ["StringLike", "StringNotLike"]:
                    if cond_type in condition:
                        conditions_dict = condition[cond_type]
                        if isinstance(conditions_dict, dict) and "aws:userid" in conditions_dict:
                            userids = conditions_dict["aws:userid"]
                            if isinstance(userids, str):
                                userids = [userids]
                            all_userids.update(userids)

            # Guardar fila en el CSV si hay datos acumulados
            if all_actions or all_userids:
                writer.writerow([
                    bucket_name,  # Eliminamos "profile"
                    "; ".join(sorted(all_userids)) if all_userids else "",
                    ", ".join(sorted(all_actions))
                ])