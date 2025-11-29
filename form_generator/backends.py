from django.contrib.auth.backends import ModelBackend
from .models import UserData
import logging
from django.contrib.auth.models import User
logger = logging.getLogger(__name__)


# extract the Django server to apply the updates.

class MailIDBackend(ModelBackend):
    def authenticate(self, request, mail_id=None, password=None, **kwargs):
        logger.debug(f"Attempting to authenticate user with mail_id: {mail_id}")
        try:
            user_data = UserData.objects.get(mail_id=mail_id)
            # user = User.objects.get(id=user_data.user_id)
            user = user_data.user  # Get the User instance
            if user.check_password(password):  # Assuming password is hashed
                logger.info(f"Authentication successful for mail_id: {mail_id}")
                return user
            else:
                logger.warning(f"Password mismatch for mail_id: {mail_id}")
                return None
        except (UserData.DoesNotExist, User.DoesNotExist):
            logger.error(f"UserData or User with mail_id {mail_id} does not exist")
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
            return None




# class MailIDBackend(ModelBackend):
#     def authenticate(self, request, mail_id=None, password=None, **kwargs):
#         logger.debug(f"Attempting to authenticate user with mail_id: {mail_id}")
#         try:
#             user_data = UserData.objects.get(mail_id=mail_id)
#
#             if user_data.password == password:  # Assuming password is stored in plain text, which is not recommended
#                 logger.info(f"Authentication successful for mail_id: {mail_id}")
#
#                 # Create or get a Django User object to associate with this UserData
#                 user, created = User.objects.get_or_create(
#                     username=user_data.mail_id,
#                     defaults={'email': user_data.mail_id}
#                 )
#
#                 return user
#             else:
#                 logger.warning(f"Password mismatch for mail_id: {mail_id}")
#                 return None
#         except UserData.DoesNotExist:
#             logger.error(f"UserData with mail_id {mail_id} does not exist")
#             return None
#         except Exception as e:
#             logger.error(f"An unexpected error occurred: {e}")
#             return None
#     # def authenticate(self, request, mail_id=None, password=None, **kwargs):
#     #     logger.debug(f"Attempting to authenticate user with mail_id: {mail_id}")
#     #     try:
#     #         user_data = UserData.objects.get(mail_id=mail_id)
#     #         user = user_data.user_name
#     #         print("userrrrrrrrrrrrrr",user)
#     #         if user.check_password(password):
#     #             logger.info(f"Authentication successful for mail_id: {mail_id}")
#     #             return user
#     #         else:
#     #             logger.warning(f"Password mismatch for mail_id: {mail_id}")
#     #             return None
#     #     except UserData.DoesNotExist:
#     #         logger.error(f"UserData with mail_id {mail_id} does not exist")
#     #         return None
#     #     except Exception as e:
#     #         logger.error(f"An unexpected error occurred: {e}")
#     #         return None
