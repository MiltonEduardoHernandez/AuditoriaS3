Los pasos son: 
1.- sso aws sso login --profile datalab-dev   
2.- assume y selecciona la cuenta 
3.- ejecuta los programas iam y buckets 

PD: no lo hice en general pero es facil-> dile a la IA que tienes un .aws/config con varias cuentas y que quieres aplicar el programa para todas las cuentas y con eso ya estaria 

en la linea 

# Usamos solo este perfil para la prueba
profiles = ["datalab-dev"]  -> deberian aparecer todas las cuentas para poder correrlo de golpe 

# Si quieres dile que te saque un documento por cada cuenta 
