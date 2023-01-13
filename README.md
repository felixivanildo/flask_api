--Note: the api token is generated based on some informations, including the current time so that way it will be a unique key every time it's requested (token expire after 30 minutes from generated) ---

First run docker compose then connect one DBMS to postgres that supports postgres connection and run the dump located on Create DB directory

          
           
-- database users and passwords
  admin: 
      username: felix@mail
      password: senha
      
  non_admin:
      username: test@
      password: test
           

-- api routes are on the api_routes.txt
