import logging
logger = logging.getLogger(__name__)
################## Generate HTML Email Template #############
def generate_notification_email_template(
        mail_title,
        mail_body_text,
        mail_footer,
        mail_data_ids,
        field_values,
        field_labels,
        primary_color='#007BFF',
        secondary_color='#f2f2f2',
        url='',
        type_=''
):
    def render_custom_data_table(data_table):
        if not data_table:
            return ''
        headers = ''.join(
            '<th style="border:1px solid {}; padding:8px; background-color:{}; color:#fff; white-space: nowrap; text-overflow: ellipsis; overflow: hidden;">{}</th>'.format(
                primary_color, primary_color, col['label']
            ) for col in data_table
        )
        num_rows = len(data_table[0]['value'])
        rows = ''
        for i in range(num_rows):
            row = ''.join(
                '<td style="border:1px solid {}; padding:8px; white-space: nowrap; text-overflow: ellipsis; overflow: hidden;">{}</td>'.format(
                    primary_color, col['value'][i]
                ) for col in data_table
            )
            rows += '<tr>{}</tr>'.format(row)
        return '''
            <div style="overflow-x:auto; max-width:100%; padding-bottom:10px;">
                <table style="width:100%; border-collapse:collapse; margin-top:15px; font-size:14px; table-layout:auto; word-wrap: break-word;">
                    <thead><tr>{}</tr></thead>
                    <tbody>{}</tbody>
                </table>
            </div>
        '''.format(headers, rows)

    def format_value(id_, value):
        # Check if the value is a list with dictionaries that have 'label' and 'value' keys
        if isinstance(value, list) and len(value) > 0 and all('label' in item and 'value' in item for item in value):
            return render_custom_data_table(value)
        # If the value is a complex object (but not a data table), recursively render it
        if isinstance(value, dict):
            return render_object(value)
        # Otherwise, just return the value as a string
        return str(value)


    def render_object(obj):
        if isinstance(obj, list):
            return ''.join('<div>{}</div>'.format(render_object(item)) for item in obj)
        elif isinstance(obj, dict):
            return ''.join(
                '<div><strong>{}</strong>: {}</div>'.format(key, format_value(key, val))
                for key, val in obj.items()
            )
        return str(obj)

    rendered_fields_html = ''.join(
        '''
        <div style="margin-bottom: 12px;">
            <strong style="color: {};">{}:</strong>
            {}
        </div>
        '''.format(
            primary_color,
            field_labels.get(id_, id_),
            format_value(id_, field_values.get(id_))
        ) for id_ in mail_data_ids
    )

    approval_buttons = ''
    if type_ == 'approve':
        approval_buttons = '''
        <div style="margin-top: 20px; display: flex;">
          <a
            href="{url}"
            target="_blank"
            style="
              background-color: #fff;
              color: 28a74;
              padding: 10px 20px;
              font-size: 16px;
              cursor: pointer;
              margin-right: 10px;
              border-radius: 5px;
              text-decoration: none;
              display: flex;
              gap: 0.5rem;
              align-items: center;
              border: 2px solid #28a74;
            "
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              class="lucide lucide-circle-check-big"
            >
              <path d="M21.801 10A10 10 0 1 1 17 3.335" />
              <path d="m9 11 3 3L22 4" />
            </svg>
            Approve
          </a>

          <a
            href="{url}"
            target="_blank"
            style="
              background-color: #fff;
              color: #dc3545;
              padding: 10px 20px;
              font-size: 16px;
              cursor: pointer;
              border-radius: 5px;
              text-decoration: none;
              display: flex;
              gap: 0.5rem;
              align-items: center;
              border: 2px solid #dc3545;
            "
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              class="lucide lucide-circle-x"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="m15 9-6 6" />
              <path d="m9 9 6 6" />
            </svg>
            Reject
          </a>
        </div>
        '''.format(url=url)
    return '''
    <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    color: #333;
                    background-color: #fafafa;
                    padding: 20px;
                    line-height: 1.6;
                    margin: 0;
                }}
                .title {{
                    color: {0};
                    margin-bottom: 20px;
                    background-color: {1};
                    padding: 10px;
                    border-radius: 5px;
                    text-align: center;
                }}
                .footer {{
                    margin-top: 30px;
                    border-top: 1px solid #ccc;
                    padding-top: 10px;
                    font-size: 0.9em;
                    color: #666;
                }}
                .content {{
                    margin: 0 auto;
                    max-width: 700px;
                    background-color: #FFF;
                    padding: 20px;
                    border-radius: 5px;
                }}
                table {{
                    border: 1px solid {0};
                    width: 100%;
                }}
                td, th {{
                    border: 1px solid {0};
                    padding: 8px;
                    white-space: nowrap;
                    text-overflow: ellipsis;
                    overflow: hidden;
                }}
                @media (max-width: 600px) {{
                    body {{
                        padding: 10px;
                    }}
                    h1 {{
                        font-size: 20px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="content">
                <h1 class="title">{2}</h1>
                <div>{3}</div>
                <div style="margin-top: 20px;">{4}</div>
                {5}
                <div class="footer">{6}</div>
            </div>
        </body>
    </html>
    '''.format(primary_color, secondary_color, mail_title, mail_body_text, rendered_fields_html, approval_buttons,
               mail_footer)
