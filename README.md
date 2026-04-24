1. pip3 install --upgrade msal requests\

2. Fill in all values above in the config section\

3. python3 honey_pipeline.py\

4. Browser opens automatically for Microsoft login\
   - Sign into your Hotmail account\
   - Grant Mail.Read permission\

5. Token cached to disk — browser won't open again
   unless cache expires\

6. Script begins polling Junk folder every 5 minutes\
