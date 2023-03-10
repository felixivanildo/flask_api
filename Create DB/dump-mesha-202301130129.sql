PGDMP                          {            mesha    14.2 (Debian 14.2-1.pgdg110+1)    14.2     ?           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            ?           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            ?           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            ?           1262    16384    mesha    DATABASE     Y   CREATE DATABASE mesha WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'en_US.utf8';
    DROP DATABASE mesha;
                postgres    false                        2615    2200    public    SCHEMA        CREATE SCHEMA public;
    DROP SCHEMA public;
                postgres    false                        0    0    SCHEMA public    COMMENT     6   COMMENT ON SCHEMA public IS 'standard public schema';
                   postgres    false    3            ?            1259    16402 
   ressources    TABLE     ?   CREATE TABLE public.ressources (
    id integer NOT NULL,
    produto character varying(30),
    descricao character varying(200),
    quantidade numeric(3,0),
    alocated_at date,
    columnto_be_retorned date
);
    DROP TABLE public.ressources;
       public         heap    postgres    false    3            ?            1259    16401    resources_id_seq    SEQUENCE     ?   CREATE SEQUENCE public.resources_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.resources_id_seq;
       public          postgres    false    212    3                       0    0    resources_id_seq    SEQUENCE OWNED BY     F   ALTER SEQUENCE public.resources_id_seq OWNED BY public.ressources.id;
          public          postgres    false    211            ?            1259    16394    userss    TABLE     ?   CREATE TABLE public.userss (
    id integer NOT NULL,
    email character varying(30) NOT NULL,
    pwd character varying(80) NOT NULL,
    role boolean DEFAULT false
);
    DROP TABLE public.userss;
       public         heap    postgres    false    3            ?            1259    16393    userss_id_seq    SEQUENCE     ?   CREATE SEQUENCE public.userss_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.userss_id_seq;
       public          postgres    false    3    210                       0    0    userss_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.userss_id_seq OWNED BY public.userss.id;
          public          postgres    false    209            f           2604    16405    ressources id    DEFAULT     m   ALTER TABLE ONLY public.ressources ALTER COLUMN id SET DEFAULT nextval('public.resources_id_seq'::regclass);
 <   ALTER TABLE public.ressources ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    212    211    212            d           2604    16397 	   userss id    DEFAULT     f   ALTER TABLE ONLY public.userss ALTER COLUMN id SET DEFAULT nextval('public.userss_id_seq'::regclass);
 8   ALTER TABLE public.userss ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    209    210    210            ?          0    16402 
   ressources 
   TABLE DATA           k   COPY public.ressources (id, produto, descricao, quantidade, alocated_at, columnto_be_retorned) FROM stdin;
    public          postgres    false    212   ?       ?          0    16394    userss 
   TABLE DATA           6   COPY public.userss (id, email, pwd, role) FROM stdin;
    public          postgres    false    210   ~                  0    0    resources_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.resources_id_seq', 4, true);
          public          postgres    false    211                       0    0    userss_id_seq    SEQUENCE SET     <   SELECT pg_catalog.setval('public.userss_id_seq', 12, true);
          public          postgres    false    209            j           2606    16407    ressources resources_pkey 
   CONSTRAINT     W   ALTER TABLE ONLY public.ressources
    ADD CONSTRAINT resources_pkey PRIMARY KEY (id);
 C   ALTER TABLE ONLY public.ressources DROP CONSTRAINT resources_pkey;
       public            postgres    false    212            h           2606    16400    userss userss_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.userss
    ADD CONSTRAINT userss_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.userss DROP CONSTRAINT userss_pkey;
       public            postgres    false    210            ?   ?   x?5??
?0Dϛ??0Ҥ?@? ???lҔ??V?ߛj?9?3?S`?%is$`f,"d73N484+?.?7??ߊ??{?]?A~??Cθ%h(??Vg?0{??dB??D?LЎ??_?????????????S??y
??t-+%?ޭ?J??(?? ??9K      ?   ?   x?Mν?0@??}f????怋	?$.??^??DE4>?&.?g?r@\??i??KF1?=?K#V??G??~ו}]A}{=?O???Cˁ??#bA?6w*9 k1?BE?b?Z??wC???/C?K3fLK)? ???E?&$?$boH)b*??7w?H)?k?7?     