# custom_components/utils/pagination.py
from math import ceil

def paginate_data(data_list, page=1, page_size=10):
    """
    Reusable pagination function.
    
    Args:
        data_list (list or queryset): The list/queryset to paginate.
        page (int): Current page number (1-based).
        page_size (int): Number of items per page.

    Returns:
        dict: {
            "results": paginated_data,
            "pagination": {
                "total": int,
                "page": int,
                "page_size": int,
                "total_pages": int,
                "has_next": bool,
                "has_previous": bool
            }
        }
    """
    try:
        page = int(page)
        page_size = int(page_size)
    except (ValueError, TypeError):
        page, page_size = 1, 10

    if page <= 0:
        page = 1
    if page_size <= 0:
        page_size = 10

    total = len(data_list)
    start = (page - 1) * page_size
    end = start + page_size
    paginated_data = data_list[start:end]
    total_pages = ceil(total / page_size) if page_size else 1

    return {
        "results": paginated_data,
        "pagination": {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        }
    }
