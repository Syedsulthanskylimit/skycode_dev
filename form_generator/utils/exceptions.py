# utils/exceptions.py

class ReceiverEmailResolutionError(Exception):
    """
    Raised when receiver email cannot be resolved from data.
    """
    def __init__(self, message):
        super().__init__(message)
        self.message = message
