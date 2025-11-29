import logging
from pywinauto import Application, timings
import time


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


import logging
from pywinauto import Application
from pywinauto.findwindows import ElementNotFoundError
import time

# Configure logging
logging.basicConfig(filename='rpa_handler.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')

class RPAHandler:
    def __init__(self, app_path, window_title, backend="uia"):
        """
        Initialize the RPAHandler with the application path and backend.
        """
        self.app_path = app_path
        self.window_title = window_title
        self.backend = backend
        self.app = None

    def start_application(self):
        """
        Launch the application and wait until it's ready.
        """
        try:
            try:
                logging.info("Attempting to connect to an already running application...")
                self.app = Application(backend=self.backend).connect(title_re=self.window_title)
            except Exception:
                logging.info("Starting a new application instance...")
                self.app = Application(backend=self.backend).start(self.app_path)

            self.app.wait_cpu_usage_lower(threshold=10)
            logging.info("Application started successfully.")
            return "Application started successfully."
        except Exception as e:
            logging.error(f"START: Failed to start application: {str(e)}")
            raise Exception(f"START: Failed to start application: {str(e)}")

    def wait_for_element(self, window, element_name, control_type, timeout=30):
        """
        Wait for an element to appear within the given timeout period.
        """
        try:
            logging.info(f"Waiting for element '{element_name}' of control type '{control_type}'... Timeout set to {timeout} seconds.")
            element = window.child_window(control_type=control_type, title=element_name)
            element.wait('exists', timeout=timeout)
            logging.info(f"Element '{element_name}' found.")
            return element
        except Exception as e:
            logging.error(f"Element '{element_name}' not found: {str(e)}")
            raise Exception(f"Element '{element_name}' not found: {str(e)}")

    def perform_task(self, actions):
        """
        Perform tasks on the application.
        :param actions: List of tasks to execute (e.g., type, click, menu_select).
        """
        self.app = Application(backend=self.backend).connect(title_re=self.window_title)

        if not self.app:
            raise Exception("EXECUTION: Application is not started. Call start_application first.")

        try:
            for action in actions:
                window_title = action.get("window_title")
                window = self.app.window(title_re=window_title)

                # Ensure the window is visible and ready before interacting
                logging.info(f"Waiting for window '{window_title}' to be visible and ready...")
                window.wait('visible', timeout=30)
                window.wait('ready', timeout=30)

                # Check if the window exists
                if not window.exists(timeout=20):
                    raise Exception(f"Window with title '{window_title}' does not exist.")

                action_type = action.get("type")

                if action_type == "type_keys":
                    logging.info(" -- Processing 'type_keys' action -- ")

                    element = window.child_window(control_type="Edit")
                    if not element.exists(timeout=20):
                        raise Exception("EXECUTION : Notepad document area not found.")

                    element.set_focus()
                    element.type_keys(action["value"], with_spaces=True)
                    logging.info(" -- Text typed successfully -- ")

                elif action_type == "click":
                    element = getattr(window, action["element"])
                    element.click()

                elif action_type == "menu_select":
                    menu_name = action.get("menu_name")
                    menu_option = action.get("menu_option")
                    menu_control_type = action.get("menu_control_type")
                    option_control_type = action.get("option_control_type")

                    menu = window.child_window(control_type=menu_control_type, title=menu_name)
                    if not menu.exists(timeout=20):
                        raise Exception(f"EXECUTION : Menu '{menu_name}' not found.")

                    menu.click_input()

                    menu_item = window.child_window(control_type=option_control_type, title=menu_option)
                    if not menu_item.exists(timeout=20):
                        raise Exception(f"EXECUTION : Menu option '{menu_option}' not found.")

                    menu_item.click_input()

                elif action_type == "save_file":
                    logging.info("Handling Save As window...")

                    # Ensure the 'Save As' window is available
                    save_as_window = self.app.window(title_re=".*Save As.*")

                    if not save_as_window.wait('exists', timeout=30):
                        raise Exception("EXECUTION : 'Save As' window not found.")

                    save_as_window.wait('visible', timeout=20)

                    # Locate the file name input field
                    file_name_input = self.wait_for_element(save_as_window, "File name:", "Edit", timeout=30)

                    file_name_input.set_focus()
                    file_name_input.type_keys(action["value"], with_spaces=True)

                    # Locate and click the 'Save' button with different search approaches
                    try:
                        save_button = save_as_window.child_window(title_re="^Save$", control_type="Button")

                        if not save_button.exists(timeout=5):
                            raise Exception("EXECUTION : 'Save' button not found using title match.")

                        save_button.click_input()
                        logging.info("Save button clicked successfully.")

                    except Exception:
                        logging.warning("Trying alternative save button search method...")
                        all_buttons = save_as_window.descendants(control_type="Button")

                        if not all_buttons:
                            raise Exception("EXECUTION : No buttons found in 'Save As' window.")

                        for button in all_buttons:
                            logging.info(f"Found button: {button.window_text()}")
                            if "save" in button.window_text().lower():
                                button.click_input()
                                logging.info("Save button clicked via fallback method.")
                                break
                        else:
                            raise Exception("EXECUTION : No matching 'Save' button found.")

                    logging.info("File saved successfully.")

            return "Tasks performed successfully."

        except Exception as e:
            logging.error(f"EXECUTION : Error performing tasks: {str(e)}")
            raise Exception(f"EXECUTION : Error performing tasks: {str(e)}")

    def close_application(self):
        """
        Close the application.
        """
        try:
            if self.app:
                self.app.kill()
            logging.info("Application closed successfully.")
            return "Application closed successfully."
        except Exception as e:
            logging.error(f"CLOSE: Failed to close application: {str(e)}")
            raise Exception(f"CLOSE: Failed to close application: {str(e)}")




# class RPAHandler:
#     def __init__(self, app_path, window_title, backend="uia"):
#         """
#         Initialize the RPAHandler with the application path and backend.
#         """
#         self.app_path = app_path
#         self.window_title = window_title
#         self.backend = backend
#         self.app = None
#
#     def start_application(self):
#         """
#         Launch the application and wait until it's ready.
#         """
#         try:
#             try:
#                 self.app = Application(backend=self.backend).connect(title_re=self.window_title)
#             except Exception:
#                 self.app = Application(backend=self.backend).start(self.app_path)
#
#             self.app.wait_cpu_usage_lower(threshold=10)
#             return "Application started successfully."
#         except Exception as e:
#             raise Exception(f"START: Failed to start application: {str(e)}")
#
#     def perform_task(self, actions):
#         """
#         Perform tasks on the application.
#         param actions: List of tasks to execute (e.g., type, click, menu_select).
#         """
#         self.app = Application(backend=self.backend).connect(title_re=self.window_title)
#
#         if not self.app:
#             raise Exception(" EXECUTION : Application is not started. Call start_application first.")
#
#         try:
#             for action in actions:
#                 window_title = action.get("window_title")
#                 window = self.app.window(title_re=window_title)
#
#                 # Ensure the window is visible and ready before interacting
#                 window.wait('visible', timeout=20)
#                 window.wait('ready', timeout=20)
#
#                 # Check if the window exists
#                 if not window.exists(timeout=10):
#                     raise Exception(f"Window with title '{window_title}' does not exist.")
#
#                 action_type = action.get("type")
#
#                 if action_type == "type_keys":
#                     print(" -- Processing 'type_keys' action -- ")
#
#                     # Updated code for text input handling
#                     element = window.child_window(control_type="Edit")
#                     if not element.exists(timeout=10):
#                         raise Exception(" EXECUTION : Notepad document area not found.")
#
#                     element.set_focus()
#                     element.type_keys(action["value"], with_spaces=True)
#                     print(" -- Text typed successfully -- ")
#
#                 elif action_type == "click":
#                     element = getattr(window, action["element"])
#                     element.click()
#
#                 elif action_type == "menu_select":
#                     menu_name = action.get("menu_name")
#                     menu_option = action.get("menu_option")
#                     menu_control_type = action.get("menu_control_type")
#                     option_control_type = action.get("option_control_type")
#
#                     menu = window.child_window(control_type=menu_control_type, title=menu_name)
#                     if not menu.exists(timeout=10):
#                         raise Exception(f" EXECUTION : Menu '{menu_name}' not found.")
#
#                     menu.click_input()
#
#                     menu_item = window.child_window(control_type=option_control_type, title=menu_option)
#                     if not menu_item.exists(timeout=10):
#                         raise Exception(f" EXECUTION : Menu option '{menu_option}' not found.")
#
#                     menu_item.click_input()
#
#                 elif action_type == "select":
#                     element = getattr(window, action["element"])
#                     element.select()
#
#
#                 elif action_type == "save_file":
#
#                     print("Handling Save As window...")
#
#                     # Ensure the 'Save As' window is available
#
#                     save_as_window = self.app.window(title_re=".*Save As.*")
#
#                     if not save_as_window.wait('exists', timeout=20):
#                         raise Exception(" EXECUTION : 'Save As' window not found.")
#
#                     save_as_window.wait('visible', timeout=10)
#
#                     # Locate the file name input field (try multiple strategies)
#
#                     file_name_input = save_as_window.child_window(control_type="Edit", found_index=0)
#
#                     if not file_name_input.exists():
#                         raise Exception(" EXECUTION : 'File name' input field not found.")
#
#                     file_name_input.set_focus()
#
#                     file_name_input.type_keys(action["value"], with_spaces=True)
#
#                     # Locate and click the 'Save' button with different search approaches
#
#                     try:
#
#                         save_button = save_as_window.child_window(title_re="^Save$", control_type="Button")
#
#                         if not save_button.exists(timeout=5):
#                             raise Exception(" EXECUTION : 'Save' button not found using title match.")
#
#                         save_button.click_input()
#
#                         print("Save button clicked successfully.")
#
#
#                     except Exception as e:
#
#                         print("Trying alternative save button search method...")
#
#                         # Try finding any available buttons and clicking the first one
#
#                         all_buttons = save_as_window.descendants(control_type="Button")
#
#                         if not all_buttons:
#                             raise Exception(" EXECUTION : No buttons found in 'Save As' window.")
#
#                         for button in all_buttons:
#
#                             print(f"Found button: {button.window_text()}")
#
#                             if "save" in button.window_text().lower():
#                                 button.click_input()
#
#                                 print("Save button clicked via fallback method.")
#
#                                 break
#
#                         else:
#
#                             raise Exception(" EXECUTION : No matching 'Save' button found.")
#
#                     print("File saved successfully.")
#
#                 # elif action_type == "save_file":
#                 #     save_as_window = self.app.window(title_re="Save As")
#                 #     save_as_window.wait('visible', timeout=20)
#                 #
#                 #     file_name_input = save_as_window.child_window(control_type="Edit", found_index=0)
#                 #     file_name_input.wait('visible', timeout=5)
#                 #     file_name_input.set_focus()
#                 #     file_name_input.type_keys(action["value"], with_spaces=True)
#                 #
#                 #     save_button = save_as_window.child_window(control_type="Button", title="Save")
#                 #     save_button.wait('visible', timeout=5)
#                 #     save_button.click_input()
#
#             return "Tasks performed successfully."
#
#         except Exception as e:
#             raise Exception(f" EXECUTION : Error performing tasks: {str(e)}")
#
#     def close_application(self):
#         """
#         Close the application.
#         """
#         try:
#             if self.app:
#                 self.app.kill()
#             return "Application closed successfully."
#         except Exception as e:
#             raise Exception(f"CLOSE: Failed to close application: {str(e)}")




# class RPAHandler:
#     def __init__(self, app_path, window_title, backend="uia"):
#         """
#         working code (2 time execution)
#
#         Initialize the RPAHandler with the application path and backend.
#         param app_path: The path to the application's executable file (e.g., 'notepad.exe').
#         param backend: The automation backend ('win32' or 'uia'). Defaults to 'uia'.
#
#         """
#         self.app_path = app_path
#         # print(f" INIT :--- 0 start application: {str(app_path)}")
#         self.window_title = window_title
#         # print(f" INIT :--- 1  start application: {str(window_title)}")
#         self.backend = backend
#         self.app = None
#
#     def start_application(self):
#         """
#         Launch the application and wait until it's ready.
#         """
#
#         try:
#             # Try to connect to an existing process first
#             try:
#                 self.app = Application(backend=self.backend).connect(title_re=self.window_title)
#                 # logger.info(" START :** Connected to existing application process.++++")
#             except Exception as e:
#                 logger.info(" START :** No existing process found. Starting a new application process.")
#                 self.app = Application(backend=self.backend).start(self.app_path)
#
#             # Wait for the application to stabilize
#             timings.wait_until_passes(60, 3, lambda: self.app.is_process_running())
#             self.app.wait_cpu_usage_lower(threshold=10)  # Wait until CPU usage is low
#             # logger.info(" START :** Application is idle and ready.")
#
#             # Debug available windows
#             windows = self.app.windows()
#             # logger.info(f" START :** Available windows: {[w.window_text() for w in windows]}")
#
#             return "Application started successfully."
#         except Exception as e:
#             # logger.error(f" START :** Failed to start application: {str(e)}")
#             raise Exception(f" START :** Failed to start application: {str(e)}")
#
#     def perform_task(self, actions):
#         """
#         Perform tasks on the application.
#         param actions: List of tasks to execute (e.g., type, click, menu_select).
#         """
#         self.app = Application(backend=self.backend).connect(title_re=self.window_title)
#
#         if not self.app:
#             raise Exception(" EXECUTION : Application is not started. Call start_application first.")
#
#         try:
#             for action in actions:
#                 window_title = action.get("window_title")
#                 # logger.info(f" EXECUTION :++ 1 Waiting for window matching title: {window_title}")
#
#                 # Debug available windows
#                 windows = self.app.windows()
#                 # logger.info(f" EXECUTION :++ 2 Available windows: {[w.window_text() for w in windows]}")
#
#                 # Match window by regex title
#                 window = self.app.window(title_re=window_title)
#                 # logger.info(f" EXECUTION :++ 3 Matched window with title: {window_title}")
#
#                 # Perform action based on type
#                 action_type = action.get("type")
#                 if action_type == "type_keys":
#                     element = getattr(window, action["element"])
#                     # logger.info(f" EXECUTION :++ 4 Typing text into element '{action['element']}': {action['value']}")
#                     element.type_keys(action["value"], with_spaces=True)
#
#                 elif action_type == "click":
#                     element = getattr(window, action["element"])
#                     # logger.info(f" EXECUTION :++ 5 Clicking element '{action['element']}'")
#                     element.click()
#
#                 elif action_type == "menu_select":
#                     # logger.info(f" EXECUTION :++ 6 Selecting menu item '{action['value']}'")
#                     window.menu_select(action["value"])
#
#             return "Tasks performed successfully."
#         except Exception as e:
#             # logger.error(f" EXECUTION :++ 7 Error performing tasks: {str(e)}")
#             raise Exception(f" EXECUTION :++ 8 Error performing tasks: {str(e)}")
#
#     def close_application(self):
#         """
#         Close the application.
#         """
#         try:
#             self.app.kill()
#             # logger.info(" CLOSE :^^ Application closed successfully.")
#             return "Application closed successfully."
#         except Exception as e:
#             # logger.error(f" CLOSE :^^ Failed to close application: {str(e)}")
#             raise Exception(f" CLOSE :^^ Failed to close application: {str(e)}")

