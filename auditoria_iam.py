import boto3
import csv
import os

# Usamos solo este perfil para la prueba
profiles = ["datalab-dev"]

# Carpeta de salida
output_folder = "salida_politicas"
os.makedirs(output_folder, exist_ok=True)

# CSV de salida para usuarios IAM y políticas relacionadas con S3
iam_csv_file = os.path.join(output_folder, "usuarios_iam_policies_s3.csv")
with open(iam_csv_file, mode="w", newline="") as iam_csvfile:
    iam_writer = csv.writer(iam_csvfile)
    iam_writer.writerow(["Usuario IAM", "Políticas relacionadas con S3"])  # Encabezados

    for profile in profiles:
        print(f"🔍 Revisando perfil: {profile}")
        session = boto3.Session(profile_name=profile)
        iam = session.client("iam")

        try:
            # Listar todos los usuarios IAM
            users = iam.list_users()["Users"]
            for user in users:
                user_name = user["UserName"]
                print(f"🔍 Analizando políticas para el usuario: {user_name}")

                # Obtener políticas adjuntas al usuario
                attached_policies = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
                s3_policies = []

                for policy in attached_policies:
                    policy_name = policy["PolicyName"]
                    policy_arn = policy["PolicyArn"]

                    # Obtener la versión de la política
                    policy_version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
                    )
                    statements = policy_version["PolicyVersion"]["Document"].get("Statement", [])
                    if not isinstance(statements, list):
                        statements = [statements]

                    # Verificar si la política contiene acciones relacionadas con S3
                    for stmt in statements:
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]

                        # Filtrar acciones relacionadas con S3
                        if any(action.startswith("s3:") for action in actions):
                            s3_policies.append(policy_name)
                            break  # No necesitamos analizar más esta política

                # Escribir en el CSV solo si hay políticas relacionadas con S3
                if s3_policies:
                    iam_writer.writerow([user_name, ", ".join(s3_policies)])
                    print(f"Usuario IAM: {user_name}, Políticas relacionadas con S3: {', '.join(s3_policies)}")

        except Exception as e:
            print(f"❌ Error al procesar el perfil {profile}: {e}")