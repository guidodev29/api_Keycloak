from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
from keycloak import KeycloakAdmin, KeycloakOpenID 
from pydantic import BaseModel
import requests

app = FastAPI()

# Configuración de Keycloak
# La URL del servidor de Keycloak y la configuración del cliente y el secreto
KEYCLOAK_SERVER_URL = "http://localhost:8080/"
REALM_NAME = "environment"
CLIENT_ID = "api-backend"
CLIENT_SECRET = "Tg1rOnfSDN0ncpTadAGjUN46eYMYvWoT"

# Configuración del cliente OpenID para la autenticación en Keycloak
keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    client_id=CLIENT_ID,
    realm_name=REALM_NAME,
    client_secret_key=CLIENT_SECRET
)

# Configuración de OAuth2 para la autenticación usando el esquema Authorization Code Bearer
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/auth",
    tokenUrl=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/token"
)

# Función para obtener la clave pública de Keycloak para verificar los tokens
def get_keycloak_public_key():
    """Recupera la clave pública desde la configuración OpenID de Keycloak"""
    openid_config_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/.well-known/openid-configuration"
    response = requests.get(openid_config_url)

    # Si la respuesta es exitosa, se obtiene el JWKS URI y la clave pública
    if response.status_code == 200:
        jwks_uri = response.json()["jwks_uri"]
        jwks_response = requests.get(jwks_uri)

        if jwks_response.status_code == 200:
            jwks = jwks_response.json()
            public_key = jwks['keys'][0]['x5c'][0]
            return f"-----BEGIN CERTIFICATE-----\n{public_key}\n-----END CERTIFICATE-----"
    
    raise Exception("Failed to retrieve public key from Keycloak")

# Función para verificar el token JWT usando la clave pública
async def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        public_key = get_keycloak_public_key()  # Obtiene la clave pública
        # Decodifica y verifica el token JWT usando la clave pública
        payload = jwt.decode(token, public_key, algorithms=["RS256"], audience="account", 
                             issuer=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

# Endpoint protegido: Solo accesible para usuarios autenticados
@app.get("/protected-endpoint")
async def protected_route(user_info: dict = Depends(verify_token)):
    """Endpoint protegido. Devuelve el estado de autenticación del usuario"""
    return {"message": "Estás autenticado", "user_info": user_info}

# Configuración del cliente administrativo de Keycloak
keycloak_admin = KeycloakAdmin(
    server_url=KEYCLOAK_SERVER_URL,
    username='admin',
    password='admin',
    client_id='admin-cli',
    realm_name='master',
    verify=True
)

# Esquema para la creación de usuarios
class UserCreateRequest(BaseModel):
    email: str
    password: str

# Endpoint para crear usuarios en Keycloak
@app.post("/create-user/")
async def create_user(user: UserCreateRequest):
    """Crea un nuevo usuario en Keycloak"""
    try:
        # Crear nuevo usuario con las credenciales proporcionadas
        user_created = keycloak_admin.create_user({
            "email": user.email,
            "username": user.email,
            "enabled": True,
            "credentials": [{"value": user.password, "type": "password"}]
        })
        return {"message": "User creado con éxito", "user_id": user_created}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Esquema para la solicitud de restablecimiento de contraseña
class ResetPasswordRequest(BaseModel):
    email: str

# Endpoint para restablecer la contraseña de un usuario
@app.post("/reset-password/")
async def reset_password(request: ResetPasswordRequest):
    """Restablece la contraseña de un usuario de Keycloak"""
    try:
        user_id = keycloak_admin.get_user_id(request.email)  # Obtiene el ID del usuario por su email
        if user_id:
            keycloak_admin.set_user_password(user_id=user_id, password="nueva_contraseña_temp", temporary=True)
            return {"message": f"Contraseña restablecida para el user {request.email}"}
        else:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint protegido para obtener todos los usuarios desde Keycloak
@app.get("/users/", dependencies=[Depends(verify_token)])
async def get_users():
    """Obtiene la lista de usuarios registrados en el realm de Keycloak"""
    try:
        users = keycloak_admin.get_users({})  # Obtiene todos los usuarios del realm
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los usuarios: {str(e)}")
