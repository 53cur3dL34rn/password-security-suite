from password_suite.logging_utils import setup_logger
from password_suite.interactive import run_menu

if __name__ == "__main__":
    logger = setup_logger()
    run_menu(logger)
