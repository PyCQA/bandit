#
# Copyright 2016 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import bandit

branches = {
    "if info is not None1": False,
    "if info is not None2": False,
    'if info["id"].startswith("B3")': False,
    'if info["id"] in ["B304", "B305"]': False,
    'elif info["id"] in ["B313" - "B320"]': False,
    'if info["id"].startswith("B3") else': False,
    'if info is not None1 else': False,
    'if info is not None2 else': False
}

# def show_coverage():

#     branch_hit = 0
#     total_branches = 0

#     for branch, hit in branches.items():
#         if hit:
#             branch_hit += 1
#             print(f"Branch '{branch}' was hit")
#         else:
#             print(f"Branch '{branch}' was not hit")

#         total_branches += 1

#     print(f"Branch coverage is {branch_hit * 100 / total_branches}%\n")

def get_url(bid):
    # where our docs are hosted
    base_url = f"https://bandit.readthedocs.io/en/{bandit.__version__}/"

    # NOTE(tkelsey): for some reason this import can't be found when stevedore
    # loads up the formatter plugin that imports this file. It is available
    # later though.
    from bandit.core import extension_loader

    info = extension_loader.MANAGER.plugins_by_id.get(bid)
    if info is not None:

        branches["if info is not None1"] = True

        return f"{base_url}plugins/{bid.lower()}_{info.plugin.__name__}.html"
    
    else:    
        branches["if info is not None1 else"] = True

    info = extension_loader.MANAGER.blacklist_by_id.get(bid)

    print("info:", info)

    if info is not None:

        branches["if info is not None2"] = True

        template = "blacklists/blacklist_{kind}.html#{id}-{name}"
        info["name"] = info["name"].replace("_", "-")

        if info["id"].startswith("B3"):  # B3XX

            branches['if info["id"].startswith("B3")'] = True

            # Some of the links are combined, so we have exception cases
            if info["id"] in ["B304", "B305"]:

                branches['if info["id"] in ["B304", "B305"]'] = True

                info = info.copy()
                info["id"] = "b304-b305"
                info["name"] = "ciphers-and-modes"
            
            elif info["id"] in [
                "B313",
                "B314",
                "B315",
                "B316",
                "B317",
                "B318",
                "B319",
                "B320",
            ]:
                
                branches['elif info["id"] in ["B313" - "B320"]'] = True

                info = info.copy()
                info["id"] = "b313-b320"
            ext = template.format(
                kind="calls", id=info["id"], name=info["name"]
            )
        else:

            branches['if info["id"].startswith("B3") else'] = True

            ext = template.format(
                kind="imports", id=info["id"], name=info["name"]
            )

        return base_url + ext.lower()
    
    else:    
        branches["if info is not None2 else"] = True

    return base_url  # no idea, give the docs main page

# --- Test Cases --- #

# show_coverage() # Nothing

# print(get_url("x"))
# show_coverage() # Invalid ID

# get_url("B301") 
# show_coverage()

# get_url("B304") # In range B304-B305
# show_coverage()

# # get_url("B3x") # B3, but invalid second 2 digits

# get_url("B313") # In range B313-B320
# show_coverage()

# get_url("B402") # Starts with B, but 1st number is not 3
# show_coverage()

# get_url("B101") 
# show_coverage()