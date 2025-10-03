# Генерація приватного ключа 2048 біт
openssl genrsa -out private.pem 2048

# Генерація публічного ключа з приватного
openssl rsa -in private.pem -pubout -out public.pem

# прочитати ключі
type private.pem
type public.pem