document.addEventListener("DOMContentLoaded", function () {

    class UserAccess {

        createGroupForm = document.getElementById("createGroupForm");
        createGroupModal = document.getElementById("createGroupModal");
        createUserForm = document.getElementById("createUserForm");
        createUserModal = document.getElementById("createUserModal");
        deleteGroupForm = document.getElementById("deleteGroupForm");
        deleteGroupModal = document.getElementById("deleteGroupModal");
        deleteUserForm = document.getElementById("deleteUserForm");
        deleteUserModal = document.getElementById("deleteUserModal");
        updateGroupForm = document.getElementById("updateGroupForm");
        updateGroupModal = document.getElementById("updateGroupModal");
        updateUserModal = document.getElementById("updateUserModal");
        updateUserForm = document.getElementById("updateUserForm");

        init() {
            this.loadUsers();
            this.loadGroups();
            this.createUserForm.addEventListener("submit", (event) => {
                event.preventDefault();
                this.createUser();
            });
            this.deleteUserForm.addEventListener("submit", (event) => {
                event.preventDefault();
                this.deleteUser(this.deleteUserModal.dataset.id);
            });
            this.createGroupForm.addEventListener("submit", (event) => {
                event.preventDefault();
                this.createGroup();
            });
            this.updateGroupForm.addEventListener("submit", (event) => {
                event.preventDefault();
                this.updateGroup();
            });
            this.deleteGroupForm.addEventListener("submit", (event) => {
                event.preventDefault();
                this.deleteGroup(this.deleteGroupForm.querySelector("[name=\"id\"]").value);
            });
            this.createGroupModal.addEventListener("show.bs.modal", event => {
                this.loadGroupMembers("#createGroupFormGroupMembers");
            });
        }

        loadUser = async function (id) {
            fetch("../api/scim/users" + "/" + id)
                .then(response => response.json())
                .then(data => {
                    if (data) {
                        // document.querySelector('#your-id[name="your-name"]')
                        document.getElementById("updateUserForm").querySelector("[name=\"id\"]").value = data.id;
                        document.getElementById("updateUserForm").querySelector("[name=\"userName\"]").value = data.userName;
                        document.getElementById("updateUserModal").querySelector("[name=\"name\"]").textContent = data.displayName + " (" + data.userName + ")";
                        document.getElementById("updateUserForm").querySelector("[name=\"givenName\"]").value = data.name.givenName;
                        document.getElementById("updateUserForm").querySelector("[name=\"familyName\"]").value = data.name.familyName;
                        document.getElementById("updateUserForm").querySelector("[name=\"email\"]").value = data.emails[0].value;
                        document.getElementById("updateUserForm").querySelector("[name=\"active\"]").checked = data.active;
                        document.getElementById("updateUserForm").querySelector("[name=\"active\"]").value = data.active;
                        // document.getElementById("updateUserForm").querySelector("[name=\"password\"]").value = data.password;
                    }
                })
                .catch(error => {
                    console.error("Error loading user:", error);
                });
        }

        loadUsers = async function () {
            fetch("../api/scim/users")
                .then(response => response.json())
                .then(data => {
                    if (!data || !data.Resources || data.Resources.length == 0) {
                        return;
                    }
                    if (this.userTable) {
                        this.userTable.destroy();
                    }
                    this.userTable = new simpleDatatables.DataTable("#users", {
                        data: {
                            headings: [
                                "ID",
                                "User Name",
                                "Display Name",
                                // "Family Name",
                                // "Given Name",
                                "Email",
                                "Active",
                                "Action"
                                // "meta", 
                                // "schemas", 
                                // "urn", 
                                // "userType"
                            ],
                            data: data.Resources.map((element) => {
                                return [
                                    element.id,
                                    element.userName,
                                    element.displayName,
                                    // element.name.familyName,
                                    // element.name.givenName,
                                    element.emails[0].value,
                                    element.active,
                                    ""
                                    // element.meta.location,
                                    // element.schemas,
                                    // element.urn,
                                    // element.userType,
                                    // element.locale,
                                    // element.phoneNumbers,
                                    // element.groups
                                ];
                            })
                        },
                        columns: [
                            {
                                select: 0,
                                hidden: true
                            },
                            {
                                select: 1,
                                sort: "asc"
                            },
                            {
                                select: 4,
                                type: "boolean"
                            },
                            {
                                select: 5,
                                sortable: false,
                                render: function (data, cell, dataIndex, cellIndex) {
                                    return "<button class=\"btn btn-success btn-sm me-1 btn-update-user\">Update</button><button class=\"btn btn-danger btn-sm btn-delete-user\">Delete</button>";
                                }
                            }
                        ]
                    });
                    this.userTable.on("datatable.init", () => {
                        document.querySelectorAll(".btn-update-user").forEach((element) => {
                            element.addEventListener("click", (event) => {
                                const index = event.target.parentElement.parentElement.dataset.index;
                                this.loadUser(this.userTable.data.data[index].cells[0].data[0].data);
                                new bootstrap.Modal(this.updateUserModal).show();
                            });
                        });
                        document.querySelectorAll(".btn-delete-user").forEach((element) => {
                            element.addEventListener("click", (event) => {
                                const index = event.target.parentElement.parentElement.dataset.index;
                                this.deleteUserForm.querySelector("[name=\"id\"]").value = this.userTable.data.data[index].cells[0].data[0].data;
                                document.getElementById("deleteUserModalTitleName").textContent = this.userTable.data.data[index].cells[1].data[0].data;
                                new bootstrap.Modal(this.deleteUserModal).show();
                            });
                        });
                    });
                })
                .catch(error => {
                    console.error("Error loading users:", error);
                });
        }

        loadGroup = async function (id) {
            fetch("../api/scim/groups" + "/" + id)
                .then(response => response.json())
                .then(data => {
                    if (data) {
                        document.getElementById("updateGroupForm").querySelector("[name=\"id\"]").value = data.id;
                        document.getElementById("updateGroupForm").querySelector("[name=\"displayName\"]").value = data.displayName;
                        document.getElementById("updateGroupModal").querySelector("[name=\"name\"]").textContent = data.displayName;
                    }
                    this.loadGroupMembers("#updateGroupFormGroupMembers", data.members);
                })
                .catch(error => {
                    console.error("Error loading group:", error);
                });
        }

        loadGroups = async function () {
            fetch("../api/scim/groups")
                .then(response => response.json())
                .then(data => {
                    if (!data || !data.Resources || data.Resources.length == 0) {
                        return;
                    }
                    if (this.groupTable) {
                        this.groupTable.destroy();
                    }
                    this.groupTable = new simpleDatatables.DataTable("#groups", {
                        data: {
                            headings: [
                                "ID",
                                "Display Name",
                                "Action"
                            ],
                            data: data.Resources.map((element) => {
                                return [
                                    element.id,
                                    element.displayName,
                                    ""
                                ];
                            })
                        },
                        columns: [
                            {
                                select: 0,
                                hidden: true
                            },
                            {
                                select: 1,
                                sort: "asc"
                            },
                            {
                                select: 2,
                                sortable: false,
                                render: function (data, cell, dataIndex, cellIndex) {
                                    return "<button class=\"btn btn-success btn-sm me-1 btn-update-group\">Update</button><button class=\"btn btn-danger btn-sm btn-delete-group\">Delete</button>";
                                }
                            }
                        ]
                    });
                    this.groupTable.on("datatable.init", () => {
                        document.querySelectorAll(".btn-update-group").forEach((element) => {
                            element.addEventListener("click", (event) => {
                                const index = event.target.parentElement.parentElement.dataset.index;
                                this.loadGroup(this.groupTable.data.data[index].cells[0].data[0].data);
                                new bootstrap.Modal(this.updateGroupModal).show();
                            });
                        });
                        document.querySelectorAll(".btn-delete-group").forEach((element) => {
                            element.addEventListener("click", (event) => {
                                const index = event.target.parentElement.parentElement.dataset.index;
                                this.deleteGroupForm.querySelector("[name=\"id\"]").value = this.groupTable.data.data[index].cells[0].data[0].data;
                                document.getElementById("deleteGroupModalTitleName").textContent = this.groupTable.data.data[index].cells[1].data[0].data;
                                new bootstrap.Modal(this.deleteGroupModal).show();
                            });
                        });
                    });
                })
                .catch(error => {
                    console.error("Error loading groups:", error);
                });
        }

        loadGroupMembers = async function (selector, members) {
            if (members && members.length > 0) {
                members.forEach((element, index, members) => {
                    if (element.value) {
                        members[index] = element.value;
                    }
                });
            } else {
                members = [];
            }
            fetch("../api/scim/users")
                .then(response => response.json())
                .then(data => {
                    if (!data || !data.Resources || data.Resources.length == 0) {
                        return;
                    }
                    if (this.groupMemberTable) {
                        this.groupMemberTable.destroy();
                    }
                    this.groupMemberTable = new simpleDatatables.DataTable(selector, {
                        data: {
                            headings: [
                                "ID",
                                "User Name",
                                "Display Name",
                                "Action"
                            ],
                            data: data.Resources.map((element) => {
                                return [
                                    element.id,
                                    element.userName,
                                    element.displayName,
                                    members.includes(element.id) ? true : false
                                ];
                            })
                        },
                        columns: [
                            {
                                select: 0,
                                hidden: true
                            },
                            {
                                select: 1,
                                sort: "asc"
                            },
                            {
                                select: 3,
                                sortable: false,
                                type: "boolean",
                                render: function (data, cell, dataIndex, cellIndex) {
                                    if (data) {
                                        // return "<button type=\"button\" class=\"btn btn-danger btn-remove-group-member\">Remove</button>";
                                        return "<div class=\"form-check form-switch\"><button type=\"button\" class=\"form-check-input checked btn-remove-group-member\"></button>";
                                    } else {
                                        // return "<button type=\"button\" class=\"btn btn-success btn-add-group-member\">Add</button>";
                                        return "<div class=\"form-check form-switch\"><button type=\"button\" class=\"form-check-input not-checked btn-add-group-member\"></button>";
                                    }
                                }
                            }
                        ]
                    });
                    this.groupMemberTable.dom.addEventListener("click", event => {
                        if (event.target.matches(".btn-remove-group-member") || event.target.matches(".btn-add-group-member")) {
                            event.preventDefault();
                            event.stopPropagation();
                            const index = parseInt(event.target.parentElement.parentElement.parentElement.dataset.index, 10);
                            this.groupMemberTable.data.data[index].cells[3].data = event.target.matches(".btn-add-group-member") ? true : false;
                            this.groupMemberTable.update();
                        }
                    });
                })
                .catch(error => {
                    console.error("Error loading group members:", error);
                });
        }

        createUser = async function () {
            const formData = new FormData(this.createUserForm);
            var data =
            {
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:User"
                ],
                "userName": formData.get("userName"),
                "password": formData.get("password"),
                "displayName": formData.get("givenName") + " " + formData.get("familyName"),
                "active": formData.get("active") == "on" ? true : false,
                "name": {
                    "familyName": formData.get("familyName"),
                    "givenName": formData.get("givenName")
                },
                "emails": [
                    {
                        "type": "work",
                        "primary": "true",
                        "value": formData.get("email")
                    }
                ]
            };
            var data = JSON.stringify(data);
            fetch("../api/scim/users", {
                method: "POST",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                },
                body: data
            }).then(response => response.json()
            ).then(data => {
                if (data.schemas && data.schemas.length > 0 && data.schemas[0] && data.schemas[0] == "urn:ietf:params:scim:schemas:core:2.0:User") {
                    bootstrap.Modal.getInstance(this.createUserModal).hide();
                    this.loadUsers();
                    this.createUserForm.reset();
                }
            })
                .catch(error => {
                    console.error("Error creating user:", error);
                });
        }

        createGroup = async function () {
            const formData = new FormData(this.createGroupForm);
            var data =
            {
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:Group"
                ],
                "displayName": formData.get("displayName")
            };
            data["members"] = [];
            this.groupMemberTable.data.data.forEach((element) => {
                if (element.cells[3].data) {
                    data["members"].push({
                        "value": element.cells[0].data[0].data
                    });
                }
            });
            var data = JSON.stringify(data);
            fetch("../api/scim/groups", {
                method: "POST",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                },
                body: data
            }).then(response => response.json()
            ).then(data => {
                if (data.schemas && data.schemas.length > 0 && data.schemas[0] && data.schemas[0] == "urn:ietf:params:scim:schemas:core:2.0:Group") {
                    bootstrap.Modal.getInstance(this.createGroupModal).hide();
                    this.loadGroups();
                    this.createGroupForm.reset()
                }
            })
                .catch(error => {
                    console.error("Error creating group:", error);
                });
        }

        updateGroup = async function () {
            const formData = new FormData(this.updateGroupForm);
            var data =
            {
                "schemas": [
                    "urn:ietf:params:scim:schemas:core:2.0:Group"
                ],
                "displayName": formData.get("displayName")
            };
            data["members"] = [];
            this.groupMemberTable.data.data.forEach((element) => {
                if (element.cells[3].data) {
                    data["members"].push({
                        "value": element.cells[0].data[0].data
                    });
                }
            });
            var data = JSON.stringify(data);
            fetch("../api/scim/groups/" + formData.get("id"), {
                method: "PUT",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                },
                body: data
            }).then(response => response.json()
            ).then(data => {
                if (data.schemas && data.schemas.length > 0 && data.schemas[0] && data.schemas[0] == "urn:ietf:params:scim:schemas:core:2.0:Group") {
                    bootstrap.Modal.getInstance(this.updateGroupModal).hide();
                    this.loadGroups();
                    this.updateGroupForm.reset();
                }
            })
                .catch(error => {
                    console.error("Error updating group:", error);
                });
        }

        deleteUser = async function () {
            const formData = new FormData(this.deleteUserForm);
            fetch("../api/scim/users/" + formData.get("id"), {
                method: "DELETE",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
            }).then()
                .then(data => {
                    if (data.status == 204) {
                        bootstrap.Modal.getInstance(this.deleteUserModal).hide();
                        this.loadUsers();
                    }
                })
                .catch(error => {
                    console.error("Error deleting user:", error);
                });
        }

        deleteGroup = async function () {
            const formData = new FormData(this.deleteGroupForm);
            fetch("../api/scim/groups/" + formData.get("id"), {
                method: "DELETE",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
            }).then()
                .then(data => {
                    if (data.status == 204) {
                        bootstrap.Modal.getInstance(this.deleteGroupModal).hide();
                        this.loadGroups();
                    }
                })
                .catch(error => {
                    console.error("Error deleting group:", error);
                });
        }
    }

    window.UserAccess = new UserAccess();
    window.UserAccess.init();
});