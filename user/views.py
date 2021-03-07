from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.contrib.auth import authenticate


class Login(APIView):
    """
    This view will create the token associated with the user once the user is
    authenticated successfully.
    """

    authentication_classes = []
    permission_classes = []

    def post(self, request, format=None, *args, **kwargs):
        try:
            data = request.data
            username = data.get('username', None)
            password = data.get('password', None)

            if not username:
                raise ValueError('username not found')
            if not password:
                raise ValueError('password not found')

            user = authenticate(username=username, password=password)
            if user is not None:
                token, _ = Token.objects.get_or_create(user=user)
                response = {
                    'token': token.key,
                    'username': user.username,
                    'email': user.email,
                    'status': status.HTTP_200_OK
                    }
            else:
                raise ValueError('Invalid Credentials')

        except ValueError as err:
            response = {'status': status.HTTP_400_BAD_REQUEST, 'error': str(err)}

        return Response(response, status=response['status'])


class Logout(APIView):
    """
    This view will delete the token associated with the user and forces
    the user to login again.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        Token.objects.get(user=request.user).delete()
        return Response({'message': 'Logged out'}, status=status.HTTP_200_OK)
