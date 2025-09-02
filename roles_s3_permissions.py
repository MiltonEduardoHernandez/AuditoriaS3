import boto3
import csv

# Palabras clave para filtrar roles
TARGET_ROLES = {
    "AWSReservedSSO_AteneaDataOps",
    "AWSReservedSSO_AteneaDevOps",
    "AWSReservedSSO_AteneaMLOps",
    "AWSReservedSSO_AteneaPowerUser"
}

# Acciones relacionadas con S3
READ_ACTIONS = {"s3:GetObject", "s3:ListBucket"}
WRITE_ACTIONS = {"s3:PutObject"}

def get_s3_permissions_and_resources(policy_document):
    """Analiza un documento de política y extrae permisos y recursos relacionados con S3."""
    read_permissions = set()
    write_permissions = set()
    resources = set()

    for statement in policy_document.get("Statement", []):
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]  # Convertir a lista si es un solo string

        statement_resources = statement.get("Resource", [])
        if isinstance(statement_resources, str):
            statement_resources = [statement_resources]  # Convertir a lista si es un solo string

        for action in actions:
            if action in READ_ACTIONS:
                read_permissions.add(action)
            if action in WRITE_ACTIONS:
                write_permissions.add(action)

        # Agregar los recursos relacionados con la política
        resources.update(statement_resources)

    return read_permissions, write_permissions, resources

def audit_roles(profile_name):
    """Realiza la auditoría de roles para un perfil específico."""
    session = boto3.Session(profile_name=profile_name)
    iam = session.client("iam")
    output_file = f"roles_s3_permissions_{profile_name}.csv"

    with open(output_file, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["RoleName", "PolicyName", "Permissions", "Resources"])  # Encabezados

        # Listar todos los roles en la cuenta
        roles = iam.list_roles()["Roles"]

        for role in roles:
            role_name = role["RoleName"]

            # Filtrar roles que contienen alguna palabra clave en TARGET_ROLES
            if not any(target in role_name for target in TARGET_ROLES):
                continue

            print(f"🔍 Analizando rol: {role_name} en el perfil {profile_name}")
            try:
                # Listar políticas adjuntas al rol
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]

                for policy in attached_policies:
                    policy_name = policy["PolicyName"]
                    policy_arn = policy["PolicyArn"]

                    # Obtener la versión de la política
                    policy_version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
                    )
                    policy_document = policy_version["PolicyVersion"]["Document"]

                    # Extraer permisos y recursos relacionados con S3
                    read_permissions, write_permissions, resources = get_s3_permissions_and_resources(policy_document)

                    # Determinar el tipo de permisos
                    if read_permissions and write_permissions:
                        permissions = "Lectura y Escritura"
                    elif read_permissions:
                        permissions = "Lectura"
                    elif write_permissions:
                        permissions = "Escritura"
                    else:
                        permissions = "Ninguno"

                    # Escribir en el archivo CSV, separando cada recurso en una fila individual
                    for resource in resources:
                        if resource.startswith("arn:aws:s3:"):  # Filtrar solo recursos S3
                            writer.writerow([
                                role_name,
                                policy_name,
                                permissions,  # Usar directamente el tipo de permisos
                                resource,  # Cada recurso en una fila separada
                                "Ninguno",  # Efecto predeterminado si no hay condiciones
                                "Ninguna",  # Tipo de condición predeterminado
                                "Ninguna"   # Valores de condición predeterminados
                            ])
                            print(f"  ➡️ Política: {policy_name}, Permisos: {permissions}, Recurso: {resource}")

            except Exception as e:
                print(f"❌ Error al analizar el rol {role_name}: {e}")

    print(f"✅ Archivo generado para el perfil {profile_name}: {output_file}")

def main():
    # Lista de perfiles a auditar
    profiles = ["datalab-dev"]  # Puedes agregar más perfiles aquí

    for profile in profiles:
        audit_roles(profile)

if __name__ == "__main__":
    main()