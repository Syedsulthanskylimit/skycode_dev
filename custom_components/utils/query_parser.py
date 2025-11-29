import logging
from collections import OrderedDict

from django.db.models import Q
import json
from datetime import datetime

# Configure logging for this module
logger = logging.getLogger(__name__)



def evaluate_conditions(conditions, operator, case_data):
    """Evaluate multiple conditions with AND/OR logic."""
    results = []
    logger.info("Evaluating conditions: %s", conditions)
    logger.info("Operator: %s", operator)
    logger.info("Case data: %s", case_data)

    for condition in conditions:
        try:
            if "conditions" in condition:
                # Nested conditions
                logger.info("Evaluating nested conditions: %s", condition)
                result = evaluate_conditions(
                    condition["conditions"], condition["operator"], case_data
                )
                logger.info("Result of nested conditions: %s", result)
            else:
                # Single condition
                logger.info("Evaluating single condition: %s", condition)
                result = evaluate_condition(condition, case_data)
                logger.info("Result of single condition: %s", result)
            results.append(result)
        except Exception as e:
            logger.error("Error evaluating condition %s: %s", condition, e, exc_info=True)
            results.append(False)  # Treat evaluation errors as False

    # Combine results based on the operator
    try:
        if operator == "AND":
            return all(results)
        elif operator == "OR":
            return any(results)
        else:
            raise ValueError(f"Unknown operator: {operator}")
    except Exception as e:
        logger.error("Error combining results with operator %s: %s", operator, e, exc_info=True)
        return False


def evaluate_condition(condition, case_data):
    """Evaluate a single condition."""
    try:
        field_id = condition.get("field_id")
        input_type = condition.get("input_type", "String")  # Default to String if missing
        operator = condition.get("operator")
        value = condition.get("value")

        logger.info("Evaluating condition for field: %s", field_id)
        logger.info("Case data provided: %s", case_data)

        if not field_id or operator is None:
            raise ValueError("Condition must contain 'field_id' and 'operator'.")

        # # Extract the field value from case_data
        # form_data = case_data.get("form_data", [])
        # bot_data = case_data.get("bot_data", [])
        # ocr_data = case_data.get("ocr_data", [])
        # integration_data = case_data("integration_data", [])
        field_value = None
         # First, check in parent_case_data
        parent_data = case_data.get("case_id", {}).get("parent_case_data", [])
        for field in parent_data:
            if field.get("field_id") == field_id:
                field_value = field.get("value")
                logger.info("Field '%s' found in parent_case_data with value: %s", field_id, field_value)
                break

        ######################### modified to include case global data on 8.7.25 #####################
        # If not found yet, check in form/bot/ocr/integration
        if field_value is None:
            # Helper function to search for field_id in a data source
            # Helper function to search for field_id in a data source
            def search_in_data(data, key):
                nonlocal field_value
                logger.info("Searching in data with key: %s", key)
                found = False
                for item in data:
                    logger.info("Item being processed: %s", item)
                    try:
                        # Use data_json directly if it's a list or dict, or parse if it's a string
                        data_json = item.get(key, [])
                        if isinstance(data_json, str):
                            try:
                                data_json = json.loads(data_json)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Error decoding JSON for %s: %s", key, e, exc_info=True)
                                continue
                        logger.info("Processing data_json: %s", data_json)

                        # Handle data_json as a single dictionary
                        if isinstance(data_json, dict):
                            if data_json.get("field_id") == field_id:
                                field_value = data_json.get("value")
                                logger.info("Field '%s' found with value: %s", field_id, field_value)
                                found = True
                            continue  # No need to iterate further

                        # Handle data_json as a list
                        if not isinstance(data_json, list):
                            logger.warning(f"Expected list or dict for %s, got %s", key, type(data_json))
                            continue
                        for field in data_json:
                            # Skip non-dict entries
                            if not isinstance(field, dict):
                                logger.debug(f"Skipping non-dict field in %s: %s", key, field)
                                continue
                            if field.get("field_id") == field_id:
                                field_value = field.get("value")
                                logger.info("Field '%s' found with value: %s", field_id, field_value)
                                found = True
                    except Exception as e:
                        logger.warning(f"Error processing item for %s: %s", key, e, exc_info=True)
                        continue
                return found
            # def search_in_data(data, key):
            #     nonlocal field_value
            #     logger.info("Searching in data with key: %s", key)
            #     found = False
            #     for item in data:
            #         logger.info("Item being processed: %s", item)
            #         try:
            #             data_json = json.loads(item.get(key, "[]"))
            #             logger.info("Decoded JSON: %s", data_json)
            #             for field in data_json:
            #                 if field.get("field_id") == field_id:
            #                     field_value = field.get("value")
            #                     logger.info("Field '%s' found with value: %s", field_id, field_value)
            #                     found = True
            #         except json.JSONDecodeError as e:
            #             logger.warning("Error decoding JSON for %s: %s", key, e, exc_info=True)
            #             continue
            #     return found

            # Check in form_data
            if search_in_data(case_data.get("form_data", []),"data_json"):

                logger.info("Field '%s' found in form_data.", field_id)

            # Check in bot_data
            elif search_in_data(case_data.get("bot_data", []),"data_schema"):
                logger.info("Field '%s' found in bot_data.", field_id)

            # Check in ocr_data
            elif search_in_data(case_data.get("ocr_data", []),"data_schema"):
                logger.info("Field '%s' found in ocr_data.", field_id)

            # Check in integration_data
            elif search_in_data(case_data.get("integration_data", []),"data_schema"):
                logger.info("Field '%s' found in integration_data.", field_id)


            # # for form in form_data:
            # #     try:
            # #         data_json = json.loads(form.get("data_json", "[]"))
            # #         for field in data_json:
            # #             if field.get("field_id") == field_id:
            # #                 field_value = field.get("value")
            # #                 break
            # #         if field_value is not None:
            # #             break
            # #     except json.JSONDecodeError as e:
            # #         logger.warning("Error decoding JSON for form data: %s", e, exc_info=True)
            # #         continue

        if field_value is None:
            # logger.warning("Field '%s' not found in case data.", field_id)
            return False

        if field_value == "":
            logger.warning("Field '%s' has an empty value.", field_id)
            return False

        # Convert field_value and value based on input_type
        try:
            field_value, value = convert_types(input_type, field_value, value)
        except Exception as e:
            logger.error("Error converting field value: %s", e, exc_info=True)
            return False

        # Evaluate the condition
        try:
            return evaluate_operator(field_value, operator, value)
        except Exception as e:
            logger.error("Error evaluating operator: %s", e, exc_info=True)
            return False





    except Exception as e:
        logger.error("Error in evaluate_condition: %s", e, exc_info=True)
        return False


def convert_types(input_type, field_value, value):
    """Convert field_value and value to the appropriate types."""
    try:
        if input_type == "Date":
            field_value = datetime.fromisoformat(field_value)
            value = datetime.fromisoformat(value)
        elif input_type == "Number":
            field_value = float(field_value)
            value = float(value)
        elif input_type == "String":
            field_value = str(field_value)
            value = str(value)
        else:
            raise ValueError(f"Unknown input type: {input_type}")
        logger.debug("Converted field_value: %s, value: %s for input type: %s", field_value, value, input_type)
        return field_value, value
    except Exception as e:
        logger.error("Error converting types for input type %s: %s", input_type, e, exc_info=True)
        raise


def evaluate_operator(field_value, operator, value):
    """Evaluate the condition based on the operator."""
    try:
        # Relational operators
        if operator == "=":
            return field_value == value
        elif operator == "!=":
            return field_value != value
        elif operator == ">":
            return field_value > value
        elif operator == ">=":
            return field_value >= value
        elif operator == "<":
            return field_value < value
        elif operator == "<=":
            return field_value <= value

        # Arithmetic operators
        elif operator == "+":
            return field_value + value
        elif operator == "-":
            return field_value - value
        elif operator == "*":
            return field_value * value
        elif operator == "/":
            if value == 0:
                raise ZeroDivisionError("Division by zero is not allowed")
            return field_value / value
        elif operator == "%":
            return field_value % value
        else:
            raise ValueError(f"Unknown operator: {operator}")

    except Exception as e:
        print(f"Error evaluating operator {operator}: {e}")
        return False

# # Utility function to handle the parsing of conditions based on the operator and field type
# def apply_operator(field, operator, value, case_data):
#     """
#     Apply the operator to the field with the value.
#     Supports arithmetic, relational, and other common operators.
#     """
#     # Mapping operators to Python comparison/operation
#     operator_mapping = {
#         "=": lambda x: x == value,
#         ">": lambda x: x > value,
#         ">=": lambda x: x >= value,
#         "<": lambda x: x < value,
#         "<=": lambda x: x <= value,
#         "!=": lambda x: x != value,
#         "+": lambda x: x + value,
#         "-": lambda x: x - value,
#         "*": lambda x: x * value,
#         "/": lambda x: x / value if value != 0 else None,  # Avoid division by zero
#     }
#
#     # Check if field exists in the case data and if operator is valid
#     field_value = case_data.get(field)
#     if field_value is None:
#         logger.error(f"Field {field} not found in case data.")
#         return False
#
#     if operator not in operator_mapping:
#         logger.error(f"Unsupported operator: {operator}")
#         return False
#
#     # Apply the operator to the field value
#     return operator_mapping[operator](field_value)
#
#
# def parse_conditions(conditions, operator, case_data):
#     """
#     Recursively parse the conditions and evaluate them against case_data.
#     """
#     results = []
#     print("case_data",case_data)
#
#     for condition in conditions:
#         if 'conditions' in condition:
#             # Nested condition
#             nested_result = parse_conditions(condition['conditions'], condition['operator'], case_data)
#             results.append(nested_result)
#             print("nested_result",nested_result)
#         else:
#             # Leaf condition
#             try:
#                 result = apply_operator(
#                     field=condition['field_id'],
#                     operator=condition['operator'],
#                     value=condition['value'],
#                     case_data=case_data
#                 )
#                 results.append(result)
#                 print("result", result)
#             except ValueError as e:
#                 logger.error(f"Error processing condition: {e}")
#                 continue
#
#     # Combine results based on the logical operator (AND/OR)
#     if operator == "AND":
#         logger.debug(f"Combining conditions with AND: {results}")
#         return all(results)  # All conditions must be True
#     elif operator == "OR":
#         logger.debug(f"Combining conditions with OR: {results}")
#         return any(results)  # At least one condition must be True
#     else:
#         logger.error(f"Unsupported logical operator: {operator}")
#         raise ValueError(f"Unsupported logical operator: {operator}")

#
# ## utility function to handle the parsing of conditions based on the operator and field type
# def apply_operator(field, operator, value):
#     """
#     Apply the operator to the field with the value.
#     Supports arithmetic, relational, and other common operators.
#     """
#     operator_mapping = {
#         "=": "",
#         ">": "__gt",
#         ">=": "__gte",
#         "<": "__lt",
#         "<=": "__lte",
#         "!=": "__ne",
#         "+": "__add",
#         "-": "__sub",
#         "*": "__mul",
#         "/": "__div",
#     }
#
#     if operator not in operator_mapping:
#         logger.error(f"Unsupported operator: {operator}")
#         raise ValueError(f"Unsupported operator: {operator}")
#
#     field_operator = f"{field}{operator_mapping[operator]}"
#     logger.debug(f"Applying operator: {field_operator} with value: {value}")
#     return Q(**{field_operator: value})
#
#
# def parse_conditions(conditions, operator):
#     """
#     Recursively parse the conditions into Django Q objects.
#     """
#     queries = []
#     for condition in conditions:
#         if 'conditions' in condition:
#             # Nested condition
#             nested_query = parse_conditions(condition['conditions'], condition['operator'])
#             queries.append(nested_query)
#         else:
#             # Leaf condition
#             try:
#                 queries.append(
#                     apply_operator(
#                         field=condition['field_id'],
#                         operator=condition['operator'],
#                         value=condition['value'],
#                     )
#                 )
#             except ValueError as e:
#                 logger.error(f"Error processing condition: {e}")
#                 continue
#
#     # Combine queries based on the operator
#     if operator == "AND":
#         logger.debug(f"Combining conditions with AND: {queries}")
#         return Q(*queries, _connector=Q.AND)
#     elif operator == "OR":
#         logger.debug(f"Combining conditions with OR: {queries}")
#         return Q(*queries, _connector=Q.OR)
#     else:
#         logger.error(f"Unsupported logical operator: {operator}")
#         raise ValueError(f"Unsupported logical operator: {operator}")
