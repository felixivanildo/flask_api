FROM python:3.8
WORKDIR /index
COPY . .
RUN pip install psycopg2
RUN pip install jinja2
RUN pip install jwt
RUN pip install jsonify
RUN pip install -r requirements.txt
EXPOSE 5000
EXPOSE 5432
ENTRYPOINT ["python"]
CMD  ["index.py"]