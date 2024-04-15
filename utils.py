
def getFilterFields(filedString):
    fields = filedString.split(",")
    fieldArray = []
    for item in fields:
        splitedValue = item.split("=")
        key = splitedValue[0]
        value = splitedValue[1]
        fieldArray.append({key: key, value: value})
    return fieldArray


def generate_access_token(userId):
    from datetime import datetime,timedelta
    from pytz import timezone
    now_utc = datetime.now(timezone('UTC'))

    # Converting to Asia/Kolkata time zone
    now_asia = now_utc.astimezone(timezone('Asia/Kolkata'))
    exp = now_utc.astimezone(timezone('Asia/Kolkata'))+timedelta(minutes=settings.ACCESS_TOKEN_TIMEOUT)
    access_token_payload = {
        "user_id": userId,
        "exp": exp,
        "iat": now_asia,
    }
    access_token = jwt.encode(
        access_token_payload, settings.SECRET_KEY, algorithm="HS256"
    )

    # access_token1 = jwt.encode(access_token_payload,
    #                           settings.SECRET_KEY, algorithm='HS256').decode('utf-8')
    return str(access_token) 


def generate_refresh_token(user):

    from datetime import datetime,timedelta
    from pytz import timezone
    now_utc = datetime.now(timezone('UTC'))

    # Converting to Asia/Kolkata time zone
    now_asia = now_utc.astimezone(timezone('Asia/Kolkata'))
    exp = now_utc.astimezone(timezone('Asia/Kolkata'))+timedelta(days=1)

    refresh_token_payload = {
        "user_id": user.id,
        "exp": exp,
        "iat": now_asia,
    }
    refresh_token = jwt.encode(
        refresh_token_payload, settings.REFRESH_TOKEN_SECRET, algorithm="HS256"
    )
    # refresh_token1 = jwt.encode(
    #     refresh_token_payload, settings.REFRESH_TOKEN_SECRET, algorithm='HS256').decode('utf-8')

    return refresh_token


def checkAndGenerateAccessToken(refreshToken):
    try:

        # header = 'Token xxxxxxxxxxxxxxxxxxxxxxxx'
        access_token = refreshToken.split(" ")[1]
        print(access_token)
        payload = jwt.decode(
            access_token, settings.REFRESH_TOKEN_SECRET, algorithms=["HS256"]
        )
        userId = payload["user_id"]

    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed("Session Timeout. Please Login Again.")
    except jwt.DecodeError:
        raise exceptions.AuthenticationFailed("Invalid Token")
    except IndexError:
        raise exceptions.AuthenticationFailed("Token prefix missing")

    return {"access_token": generate_access_token(userId)}


def generateGUId():
    return str(uuid.uuid4())