<template>
    <div style="background-color: #1f2229;height: 100vh;">
        <div style="display: flex;">
            <v-dialog max-width="500">
                <template v-slot:activator="{ props: activatorProps }">
                    <v-btn
                    v-bind="activatorProps"
                    text="Add Target"
                    variant="tonal"
                    style="margin-left: 1rem;"
                    ></v-btn>
                </template>

                <template v-slot:default="{ isActive }">
                    <v-card title="Add Target">
                        <div style="margin-left: 2rem;margin-right: 1rem;margin-bottom: 1rem;">
                            <v-text>URL</v-text>
                            <v-text-field type="text" id="URL" v-model="newEntry.url" required/>
                        </div>
                        <div style="margin-left: 2rem;margin-right: 1rem;margin-bottom: 1rem;">
                            <v-text>Description</v-text>
                            <v-textarea no-resize v-model="newEntry.desc"></v-textarea>
                        </div>
                    <v-card-actions>
                        <v-spacer></v-spacer>

                        <v-btn
                        text="Cancel"
                        @click="isActive.value = false"
                        ></v-btn>
                        <v-btn
                        text="Add"
                        color="success"
                        @click="addEntry"
                        ></v-btn>
                    </v-card-actions>
                    </v-card>
                </template>
            </v-dialog>
            <v-dialog max-width="500">
                <template v-slot:activator="{ props: activatorProps }">
                    <v-btn
                    v-bind="activatorProps"
                    text="Add To Group"
                    variant="tonal"
                    style="margin-left: 1rem;"
                    @click="addGroup"
                    ></v-btn>
                </template>
                
                <template v-slot:default="{ isActive }">
                    <div v-if="showDialog">
                    <v-card title="Add Group">
                        <div style="margin-left: 2rem;margin-right: 1rem;margin-bottom: 1rem;">
                            <v-text >Group Name</v-text>
                            <v-text-field style="margin-top:1rem" type="text" id="gname" v-model="groupName" required/>
                        </div>
                        <div style="margin-left: 2rem;margin-right: 1rem;margin-bottom: 1rem;">
                            <v-text >Group Description</v-text>
                            <v-textarea no-resize v-model="groupDesc" style="margin-top:1rem"></v-textarea>
                        </div>
                        <div style="max-height:20rem;min-width: 30rem;overflow-y:auto;overflow-x: hidden;">
                        <v-data-table
                        :items="selectedEntries"
                        hide-default-footer
                        style="margin-left: 2rem;margin-right: 1rem;margin-bottom: 1rem;"
                        >
                        </v-data-table>
                        </div>
                    <v-card-actions>
                        <v-spacer></v-spacer>

                        <v-btn
                        text="Cancel"
                        @click="isActive.value = false"
                        ></v-btn>
                        <v-btn
                        text="Add"
                        color="success"
                        @click="addGrouptables"
                        ></v-btn>
                    </v-card-actions>
                    </v-card>
                    </div>
                    <div v-else>
                        <v-card>
                            <div style="margin:2rem;">
                            <p style="color:red;">Unable to group</p>
                            <p style="margin:1rem">Please select atleast 2 targets to create a group </p>
                            </div>
                            <v-card-actions>
                            <v-spacer></v-spacer>

                            <v-btn
                            text="Cancel"
                            @click="isActive.value = false"
                            ></v-btn>
                            </v-card-actions>
                        </v-card>
                    </div>
                </template>
                
            </v-dialog>
        </div>

        <div style="display: flex;">
            <div :style="{ width: `${this.divWidth}px`,margin:'1rem' }">
                <h3 style="text-align:center">Targets</h3>
                <v-container>
                    <v-row>
                        <v-col cols="25">
                        <v-data-table
                            height="700"
                            :items="entries"
                            density="compact"
                            item-key="name"
                            hide-default-footer
                        >
                        <template v-slot:item.select="{ item }">
                        <v-checkbox
                            v-model="item.select"
                        ></v-checkbox>
                        </template>
                        <template v-slot:item.url="{ item }">
                            <div class="text-wrap" style="max-width: 200px;">{{ item.url }}</div>
                        </template>
                        <template v-slot:item.desc="{ item }">
                            <div class="text-wrap" style="max-width: 250px;overflow-x:auto">{{ item.desc }}</div>
                        </template>
                        </v-data-table>
                        </v-col>
                    </v-row>
                </v-container>
            </div>
            <div :style="{ width: `${this.divWidth}px`,margin:'1rem' }">
                <h3 style="text-align:center;">Groups</h3>
                <v-container>
                    <v-row>
                        <v-col cols="25">
                        <v-data-table
                            height="700"
                            :items="groups"
                            density="compact"
                            item-key="name"
                            hide-default-footer
                        >
                        <template v-slot:item.select="{ item }">
                        </template>
                        </v-data-table>
                        </v-col>
                    </v-row>
                </v-container>
            </div>
        </div>
    
    </div>
  </template>
  
  <script>
  export default {
  name: 'TargetsPage',
  data() {
    return {
      entries: [],
      selectedEntries: [],
      groupName: "",
      groups:[],
      showDialog:true,
      divWidth: (window.innerWidth / 2)-100,
      newEntry: {
        url: '',
        desc: '',
        select: false // Use 'desc' for consistency with headers
      },
    };
  },
  computed: {
  computedWidth() {
    return (window.innerWidth)/2;
  }
  },

  methods: {
    addEntry() {
      if (this.newEntry.url.trim() && this.newEntry.desc.trim()) {
        this.entries.push({ ...this.newEntry });
        console.log(this.entries)
        this.clearNewEntry(); 
      } else {
        console.warn('Please enter a valid URL and description.');
      }
    },
    clearNewEntry() {
      this.newEntry.url = '';
      this.newEntry.desc = '';
    },
    addGroup() {
        this.selectedEntries = this.entries.filter(entry => entry.select);
        console.log(this.selectedEntries)
        if(this.selectedEntries.length<2){
            this.showDialog=false
        }
        else{
            this.showDialog=true
        }
    },
    // addGrouptables() {
        
    // }
  }
  
};

  </script>